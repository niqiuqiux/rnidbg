pub mod library_resolver;
pub mod library_file;
pub mod svc_memory;

use std::cell::UnsafeCell;
use std::cmp::max;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use anyhow::anyhow;
use bytes::{BufMut, Bytes, BytesMut};
use indexmap::IndexMap;
use log::{error, info, warn};
use crate::backend::{Backend, Permission, RegisterARM64};
use crate::elf::abi::{*};
use crate::elf::parser::ElfFile;
use crate::elf::segment::ElfSegmentData;
use crate::elf::symbol::ElfSymbol;
use crate::elf::symbol_structure::SymbolLocator;
use crate::emulator::{AndroidEmulator, MMAP_BASE, RcUnsafeCell, STACK_BASE, STACK_SIZE_OF_PAGE, VMPointer};
use crate::emulator::memory::MemoryMap;
use crate::linux::{LinuxModule, PAGE_ALIGN};
use crate::linux::init_fun::{AbsoluteInitFunction, InitFunction, LinuxInitFunction};
use crate::linux::symbol::{LinuxSymbol, ModuleSymbol, WEAK_BASE};
use crate::memory::library_file::{LibraryFile, LibraryFileTrait};
use crate::memory::svc_memory::HookListener;
use crate::tool;
use crate::tool::{align_addr, align_size, Alignment, get_segment_protection};

/// Bytes from TPIDR_EL0 to the first ELF TLS byte. Bionic TCB slots occupy
/// the low offsets (`__errno` is `*(TPIDR+8)+…`, stack canary is slot 5).
const ELF_TLS_TPREL_BIAS: i64 = 0x100;

fn elf_tls_tprel(symbol: Option<&ElfSymbol>, addend: i64) -> i64 {
    ELF_TLS_TPREL_BIAS + symbol.map(|s| s.value as i64).unwrap_or(0) + addend
}

pub(crate) struct ModuleMemRegion {
    pub virtual_address: u64,
    pub begin: u64,
    pub end: u64,

    pub perms: u32,
    pub offset: i64,
}

impl ModuleMemRegion {
    pub fn new(virtual_address: u64, begin: u64, end: u64, perms: u32, offset: i64) -> ModuleMemRegion {
        ModuleMemRegion {
            virtual_address,
            begin,
            end,
            perms,
            offset
        }
    }
}

pub struct AndroidElfLoader<'a, T: Clone> {
    stack_size: usize,
    backend: Backend<'a, T>,
    stack_base: u64,
    environ: VMPointer<'a, T>,
    hook_listeners: Vec<Box<dyn HookListener<'a, T>>>,
    cache_hook: HashMap<u64, u64>,

    pub(crate) mmap_base: u64,
    pub(crate) sp: u64,
    pub(crate) memory_map: HashMap<u64, MemoryMap>,
    pub(crate) temp_memory: HashMap<u64, usize>,
    pub(crate) modules: IndexMap<String, RcUnsafeCell<LinuxModule<'a, T>>>,
    pub(crate) malloc: Option<LinuxSymbol>,
    pub(crate) free: Option<LinuxSymbol>,
    tlsdesc_resolver: Option<u64>,
}

impl<'a, T: Clone> AndroidElfLoader<'a, T> {
    pub(crate) fn new(
        backend: Backend<'a, T>,
        pid: u32,
        proc_name: String
    ) -> anyhow::Result<(AndroidElfLoader<'a, T>, u64)> {
        let stack_size = STACK_SIZE_OF_PAGE * PAGE_ALIGN;
        backend.mem_map(STACK_BASE - stack_size as u64, stack_size, (Permission::READ | Permission::WRITE).bits())
            .expect("failed to init stack");

        let mut memory = AndroidElfLoader {
            mmap_base: MMAP_BASE,
            stack_size,
            backend,
            stack_base: 0,
            sp: 0,
            environ: VMPointer::null(),
            hook_listeners: vec![],
            memory_map: HashMap::with_capacity(64),
            modules: IndexMap::new(),
            malloc: None, free: None,
            temp_memory: HashMap::new(),
            cache_hook: HashMap::new(),
            tlsdesc_resolver: None,
        };
        memory.set_stack_point(STACK_BASE);

        let (environ, errno) = memory.init_tls(pid, proc_name)?;
        errno.write_i32_with_offset(0, 0)?;

        memory.environ = environ;

        Ok((memory, errno.addr))
    }

    pub fn find_module_by_address(&self, addr: u64) -> Option<RcUnsafeCell<LinuxModule<'a, T>>> {
        for (_, module_cell) in &self.modules {
            let module = unsafe { &*module_cell.get() };
            if module.base <= addr && addr < module.base + module.size as u64 {
                return Some(module_cell.clone());
            }
        }
        None
    }

    pub fn set_mmap_base(&mut self, mmap_base: u64) {
        self.mmap_base = mmap_base;
    }

    /// Tiny RX stub: `ldr x0, [x0, #8]; ret` for `R_AARCH64_TLSDESC`.
    fn ensure_tlsdesc_resolver(&mut self) -> u64 {
        if let Some(addr) = self.tlsdesc_resolver {
            return addr;
        }
        const STUB: u64 = 0xfffc0000;
        let _ = self.backend.mem_map(
            STUB,
            PAGE_ALIGN,
            (Permission::READ | Permission::EXEC).bits(),
        );
        // ldr x0, [x0, #8] ; ret
        let _ = self.backend.mem_write(STUB, &[0x00, 0x04, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6]);
        self.tlsdesc_resolver = Some(STUB);
        STUB
    }

    pub fn load_virtual_module(&mut self, name: String, symbols: std::collections::HashMap<String, u64>) -> RcUnsafeCell<LinuxModule<'a, T>> {
        let module = Rc::new(UnsafeCell::new(LinuxModule::create_virtual_module(name.clone(), symbols)));
        let mm = module.clone();
        self.modules.insert(name.clone(), module);
        mm
    }

    pub(crate) fn release_tmp_memory(&mut self) {
        for (base, size) in &self.temp_memory {
            let _ = self.backend.mem_unmap(*base, *size);
        }
        self.temp_memory.clear();
    }

    /// Release all cached libraries
    pub(crate) fn release_cached_library(&self) {
        for (_, module_cell) in &self.modules {
            let module = unsafe { &mut *module_cell.get() };
            module.init_function_list.clear();
            if let Some(elf_file_cell) = &module.elf_file {
                let elf_file = unsafe { &mut *elf_file_cell.get() };
                elf_file.program_headers.clear();
                elf_file.section_headers.clear();
            }
        }
    }

    pub(crate) fn load_internal(&mut self, library_file: LibraryFile, force_init: bool, emulator: &AndroidEmulator<'a, T>) -> anyhow::Result<RcUnsafeCell<LinuxModule<'a, T>>> {
        let module = self.load_library_file_internal(library_file, emulator)?;
        let module_base = unsafe { &*module.get() }.base;

        self.resolve_symbols(!force_init, emulator)?;

        for (name, m_cell) in &self.modules {
            let m = unsafe { &mut *m_cell.get() };
            let force_call = force_init && module_base == m.base;

            if option_env!("SHOW_INIT_FUNC_CALL").unwrap_or("0") == "1" {
                info!("Call init functions for {}", name);
            }

            m.call_init_functions(force_call, emulator)?;
            m.init_function_list.clear();
            if emulator.last_exit_status().is_some() {
                break;
            }
        }
        unsafe {
            (&*module.get()).ref_cnt.fetch_add(1, Ordering::SeqCst);
        }

        Ok(module.clone())
    }

    pub(crate) fn resolve_symbols(&mut self, show_warning: bool, emulator: &AndroidEmulator<'a, T>) -> anyhow::Result<()> {
        for (name, module_cell) in &self.modules {
            let m = unsafe { &mut *module_cell.get() };
            let Some(elf_file_cell) = m.elf_file.as_ref() else {
                // Virtual modules (libandroid.so, …) have no ELF.
                continue;
            };
            let elf_file = unsafe { &*elf_file_cell.get() };

            let mut resolved_symbol = Vec::new();
            for module_symbol in &m.unresolved_symbol {
                let resolved = module_symbol.resolve(emulator, &self.modules, true, &self.hook_listeners, &mut self.cache_hook, elf_file);
                if let Ok(resolved) = resolved {
                    resolved_symbol.push(resolved);
                    //resolved.relocation(m, elf_file, &self.backend)?;
                } else if show_warning {
                    warn!("Failed to resolve symbol: {}", name);
                }
            }

            for x in resolved_symbol {
                x.relocation(m, elf_file, &self.backend)?;
            }
        }
        Ok(())
    }

    fn load_library_file_internal(&mut self, library_file: LibraryFile, emulator: &AndroidEmulator<'a, T>) -> anyhow::Result<RcUnsafeCell<LinuxModule<'a, T>>> {
        let elf_file_cell = ElfFile::from_buffer(library_file.map_buffer()?);
        let elf_file = unsafe { &*elf_file_cell.get() };

        if elf_file.version != 1 {
            return Err(anyhow!("Unsupported elf version"));
        }
        if elf_file.encoding != 1 {
            return Err(anyhow!("Only support endianness: LSB"));
        }
        if elf_file.object_size == 1 {
            return Err(anyhow!("Must be 64-bit: elf class"))
        }
        if elf_file.arch != 0xB7 {
            return Err(anyhow!("Must be 64-bit: elf arch ({}), path: {}", elf_file.arch, library_file.real_path()))
        }

        let mut bound_high = 0u64;
        let mut align = 0u64;
        if elf_file.num_ph > 0 {
            for i in 0..elf_file.num_ph {
                let ph = elf_file.get_program_header(i as usize)
                    .expect("get_program_header failed: calc bound_high");
                if ph.typ == PT_LOAD && ph.mem_size > 0 {
                    let high = ph.virtual_address + ph.mem_size as u64;
                    if bound_high < high {
                        bound_high = high;
                    }
                    if ph.align > align {
                        align = ph.align;
                    }
                }
            }
        } else {
            return Err(anyhow!("ph_num > 0"))
        }

        let base_align = max(align, PAGE_ALIGN as u64);
        let load_base = ((self.mmap_base - 1) / base_align + 1) * base_align;

        let mut load_virtual_address = 0u64;
        let size = align_addr(0, bound_high, base_align as i64).size;
        self.set_mmap_base(load_base + size as u64);

        let mut eh_frame_header = None;
        let mut last_alignment: Option<Alignment> = None;
        let mut regions: Vec<ModuleMemRegion> = Vec::with_capacity(5);
        let mut dynamic_structure = None;
        let mut arm_ex_idx = None;

        for i in 0..elf_file.num_ph as usize {
            let ph = elf_file.get_program_header(i)
                .expect("get_program_header failed: calc align");
            match ph.typ {
                PT_LOAD => {
                    let mut prot = get_segment_protection(u32::from_le_bytes(ph.flags.to_le_bytes()));
                    if prot == Permission::NONE.bits() {
                        prot = Permission::ALL.bits();
                    }

                    let begin = load_base + ph.virtual_address;
                    if load_virtual_address == 0 {
                        load_virtual_address = begin;
                    }

                    let check = align_addr(begin, ph.mem_size as u64, max(PAGE_ALIGN as i64, ph.align as i64));
                    let region_size = regions.len();
                    let last = if region_size == 0 { None } else { Some(&regions[region_size - 1]) };
                    let overall = if let Some(last) = last {
                        if check.address >= last.begin && check.address < last.end {
                            Some(last)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(overall) = overall {
                        let overall_size = overall.end - check.address;
                        let perms = overall.perms | prot;
                        self.backend.mem_protect(check.address, overall_size as usize, perms)
                            .expect("mem_protect failed");
                        if ph.mem_size as u64 > overall_size {
                            let mut alignment = self.mem_map(begin + overall_size, ph.mem_size as usize - overall_size as usize, prot, library_file.name(), max(PAGE_ALIGN as u64, ph.align));
                            regions.push(ModuleMemRegion::new(begin, alignment.address, alignment.address + alignment.size as u64, prot, ph.virtual_address as i64));
                            if let Some(last_alignment) = last_alignment {
                                if last_alignment.begin + last_alignment.data_size > begin {
                                    return Err(anyhow!("last_alignment.begin + last_alignment.data_size > begin"));
                                }
                            }
                            alignment.begin = begin;
                            last_alignment = Some(alignment);
                        }
                    }
                    else {
                        let mut alignment = self.mem_map(begin, ph.mem_size as usize, prot, library_file.name(), max(PAGE_ALIGN as u64, ph.align));
                        regions.push(ModuleMemRegion::new(begin, alignment.address, alignment.address + alignment.size as u64, prot, ph.virtual_address as i64));
                        if let Some(last_alignment) = last_alignment {
                            let base = last_alignment.address + last_alignment.size as u64;
                            let off = alignment.address as i64 - base as i64;
                            if off < 0 {
                                return Err(anyhow!("off < 0"));
                            }
                            if off > 0 {
                                self.backend.mem_map(base, off as usize, Permission::NONE.bits())
                                    .expect("mem_map failed");
                                if self.memory_map.insert(base, MemoryMap::new(base, off as usize, Permission::NONE.bits())).is_some() {
                                    warn!("mem_map replace exists memory map base=0x{:X}", base);
                                }
                            }
                        }
                        alignment.begin = begin;
                        last_alignment = Some(alignment);
                    }

                    let load_data = match ph.data {
                        ElfSegmentData::PtLoad(data) => data.get_value()?,
                        _ => return Err(anyhow!("ph.data is not PtLoad"))
                    };
                    load_data.write_to(begin, &self.backend);
                    if prot & Permission::EXEC.bits() != 0 {
                        neutralize_pac_bti(&self.backend, begin, load_data.buffer.len());
                    }
                    if let Some(last_align) = last_alignment.as_mut() {
                        last_align.data_size = load_data.buffer.len() as u64;
                    }
                }
                PT_DYNAMIC => {
                    dynamic_structure = match ph.data {
                        ElfSegmentData::DynamicStructure(data) => Some(data.get_value()?),
                        _ => {
                            return Err(anyhow!("ph.data is not DynamicStructure"));
                        }
                    };
                }
                PT_INTERP => {}
                PT_GNU_EH_FRAME => {
                    eh_frame_header = match ph.data {
                        ElfSegmentData::GnuEhFrameHeader(data) => Some(data),
                        _ => {
                            return Err(anyhow!("ph.data is not GnuEhFrameHeader"));
                        }
                    };
                }
                PT_ARM_EXIDX => {
                    arm_ex_idx = match ph.data {
                        ElfSegmentData::ArmExIdx(data) => Some(data),
                        _ => {
                            return Err(anyhow!("ph.data is not ArmExIdx"));
                        }
                    };
                }
                _ => {}
            }
        }

        if dynamic_structure.is_none() {
            // Static ET_EXEC / no PT_DYNAMIC: map the image and run its entry.
            let so_name = library_file.name();
            if load_virtual_address == 0 {
                return Err(anyhow!("load_virtual_address is 0"));
            }
            let mut module = LinuxModule::new(
                load_virtual_address,
                load_base,
                size,
                so_name.clone(),
                None,
                Vec::new(),
                VecDeque::new(),
                IndexMap::new(),
                regions,
                arm_ex_idx,
                eh_frame_header,
                None,
                Some(elf_file_cell.clone()),
                None,
            );
            module.entry_point = elf_file.entry_point as u64;
            info!("loaded static executable {} entry=0x{:x}", so_name, module.entry_point);
            let module = Rc::new(UnsafeCell::new(module));
            self.modules.insert(so_name, module.clone());
            return Ok(module);
        }

        let dynamic_structure = dynamic_structure.unwrap();
        if dynamic_structure.relr_size > 0 && dynamic_structure.relr_offset > 0 {
            self.apply_relr(load_base, dynamic_structure.relr_offset as u64, dynamic_structure.relr_size)?;
        }
        let so_name = dynamic_structure.so_name(library_file.name())?;

        let mut needed_libraries = IndexMap::new();
        for needed_library in dynamic_structure.needed_libraries()? {
            info!("{} needed dependency {}", so_name, needed_library);
            let needed_library_file = self.modules.get(&needed_library);
            if let Some(needed_library_file) = needed_library_file {
                unsafe { &*needed_library_file.get() }.ref_cnt.fetch_add(1, Ordering::Relaxed);
                let base_name = get_base_name(needed_library.as_str());
                needed_libraries.insert(base_name, needed_library_file.clone());
                continue
            }
 
            let needed_library_file = library_file.resolve_library(needed_library.as_str())
                .or_else(|_| library_resolver::resolve_library_static(emulator, needed_library.as_str()));

            if needed_library_file.is_err() {
                return Err(anyhow!("Failed to resolve library: {}", needed_library));
            }

            if let Ok(needed_library_file) = needed_library_file {
                let needed = self.load_library_file_internal(needed_library_file, emulator)?;
                unsafe { &*needed.get() }.ref_cnt.fetch_add(1, Ordering::Relaxed);
                let base_name = get_base_name(needed_library.as_str());
                needed_libraries.insert(base_name, needed);
            }
        }

        for (_, module) in &self.modules {
            let linux_module = unsafe { &mut *module.get() };
            linux_module.unresolved_symbol.retain(|symbol| {
                let resloved = symbol.resolve(emulator, &linux_module.needed_libraries, false, &self.hook_listeners, &mut self.cache_hook, elf_file);
                if let Ok(resloved) = resloved {
                    resloved.relocation_ex(&mut linux_module.resolved_symbol, elf_file, &self.backend).ok();
                    return true;
                }
                return false;
            });
        }

        let mut list: Vec<ModuleSymbol> = Vec::new();
        let mut resolved_symbols: Vec<ModuleSymbol> = Vec::new();
        for relocation in dynamic_structure.relocations() {
            let typ = relocation.typ();
            if typ == 0 {
                warn!("relocation typ is 0");
                continue
            }
            let symbol = if relocation.sym() == 0 { None } else {
                relocation.symbol()
                    .map_err(|e| panic!("Failed to get symbol by name: {:?}", e))
                    .ok()
            };
            let sym_value = symbol.as_ref().map(|s| s.value).unwrap_or(0);
            let relocation_addr = VMPointer::new(load_base + relocation.offset(), 0, self.backend.clone());

            let mut module_symbol: Option<ModuleSymbol> = None;
            match typ as u32 {
                R_AARCH64_ABS64 => {
                    // RELA: use r_addend. REL: the addend lives in the slot.
                    let offset = if relocation.explicit_addend {
                        relocation.addend
                    } else {
                        relocation_addr.read_i64_with_offset(0)?
                    };
                    module_symbol = self.resolve_symbol(load_base, &symbol, &relocation_addr, so_name.as_str(), &needed_libraries, offset as u64, emulator, elf_file)
                        .map_err(|e| warn!("resolve symbol failed: {:?}", e))
                        .ok();
                    if module_symbol.is_none() {
                        list.push(ModuleSymbol::new(so_name.clone(), load_base as i64, symbol.clone(), relocation_addr.addr, "".to_string(), offset as u64));
                    } else {
                        resolved_symbols.push(module_symbol.unwrap());
                    }
                }
                R_AARCH64_RELATIVE => {
                    if sym_value == 0 {
                        let base = load_base + relocation.addend as u64;
                        relocation_addr.write_u64(base)?;
                    } else {
                        panic!("R_AARCH64_RELATIVE sym_value is not 0");
                    }
                }
                R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                    module_symbol = self.resolve_symbol(load_base, &symbol, &relocation_addr, so_name.as_str(), &needed_libraries, relocation.addend as u64, emulator, elf_file)
                        .map_err(|e| warn!("resolve symbol failed: {:?}", e))
                        .ok();
                    if module_symbol.is_none() {
                        list.push(ModuleSymbol::new(so_name.clone(), load_base as i64, symbol.clone(), relocation_addr.addr, "".to_string(), relocation.addend as u64));
                    } else {
                        resolved_symbols.push(module_symbol.unwrap());
                    }
                }
                R_AARCH64_IRELATIVE => {
                    let resolver = load_base + relocation.addend as u64;
                    let resolved = emulator.resolve_gnu_ifunc(resolver);
                    relocation_addr.write_u64(resolved)?;
                }
                R_AARCH64_TLS_TPREL => {
                    let tprel = elf_tls_tprel(symbol.as_ref(), relocation.addend);
                    relocation_addr.write_u64(tprel as u64)?;
                }
                R_AARCH64_TLS_DTPMOD => {
                    // Static TLS: one module id is enough for fail-soft libc++.
                    relocation_addr.write_u64(1)?;
                }
                R_AARCH64_TLS_DTPREL => {
                    let dtprel = symbol.as_ref().map(|s| s.value as i64).unwrap_or(0) + relocation.addend;
                    relocation_addr.write_u64(dtprel as u64)?;
                }
                R_AARCH64_TLSDESC => {
                    // Descriptor: [resolver, tprel]. Resolver returns the argument
                    // (offset from TPIDR_EL0). Matches aarch64 TLSDESC static form.
                    let tprel = elf_tls_tprel(symbol.as_ref(), relocation.addend);
                    let resolver = self.ensure_tlsdesc_resolver();
                    relocation_addr.write_u64(resolver)?;
                    relocation_addr.write_u64_with_offset(8, tprel as u64)?;
                }
                R_AARCH64_COPY => {
                    panic!("R_AARCH64_COPY relocations are not supported")
                }
                R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT | R_ARM_COPY | R_ARM_ABS32 => {
                    panic!("Not Support Arm32");
                }
                _ => {
                    error!("Unsupported relocation type: {}", typ);
                }
            }
        }

        let mut init_function_list = VecDeque::new();
        let pre_init_array_size = dynamic_structure.preinit_array_size;
        let executable = elf_file.file_type == 2 || pre_init_array_size > 0;
        if executable {
            let count = pre_init_array_size / 8;
            if count > 0 {
                let pointer = load_base + dynamic_structure.preinit_array_offset as u64;
                for i in 0..count {
                    let ptr = VMPointer::new(pointer + (i * 8) as u64, 0, self.backend.clone());

                    if option_env!("SHOW_INIT_FUNC_PUSH").unwrap_or("") == "1" {
                        let mut address = ptr.read_u64_with_offset(0)?;
                        if address == 0 {
                            address = ptr.addr;
                        }
                        println!("[{}] offset: 0x{:X} (push)", so_name, address - load_base);
                    }

                    init_function_list.push_back(InitFunction::ABSOLUTE(AbsoluteInitFunction::new(load_base, so_name.clone(), ptr)?))
                }
            }
        }
        if elf_file.file_type == 3 {
            let init = dynamic_structure.init;
            if init > 0 {
                init_function_list.push_back(InitFunction::LINUX(LinuxInitFunction::new(load_base, so_name.clone(), init as u64)));
            }

            let init_array_size = dynamic_structure.init_array_size;
            let count = init_array_size / 8;
            if count > 0 {
                let pointer = load_base + dynamic_structure.init_array_offset as u64;
                for i in 0..count {
                    let ptr = VMPointer::new(pointer + (i * 8) as u64, 0, self.backend.clone());

                    if option_env!("SHOW_INIT_FUNC_PUSH").unwrap_or("") == "1" {
                        let mut address = ptr.read_u64_with_offset(0)?;
                        if address == 0 {
                            address = ptr.addr;
                        }
                        println!("[{}] offset: 0x{:X} (push)", so_name, address - load_base);
                    }

                    init_function_list.push_back(InitFunction::ABSOLUTE(AbsoluteInitFunction::new(load_base, so_name.clone(), ptr)?))
                }
            }
        }

        let dynsym = dynamic_structure.symbol_structure.get_value()?;
        let symbol_tab_section = elf_file.find_section_by_type(SHT_SYMTAB)
            .ok();
        if load_virtual_address == 0 {
            return Err(anyhow!("load_virtual_address is 0"));
        }

        let mut module = LinuxModule::new(
            load_virtual_address,
            load_base,
            size,
            so_name.clone(),
            Some(SymbolLocator::SymbolStructure(dynsym)),
            list,
            init_function_list,
            needed_libraries,
            regions,
            arm_ex_idx,
            eh_frame_header,
            symbol_tab_section,
            Some(elf_file_cell.clone()),
            Some(dynamic_structure),
            //Some(library_file)
        );

        for symbol in resolved_symbols {
            symbol.relocation(&mut module, elf_file, &self.backend)?;
        }

        if executable {
            for (_, module_cell) in &self.modules {
                let linux_module = unsafe { &mut *module_cell.get() };
                for (name, module_symbol) in linux_module.resolved_symbol.iter() {
                    let symbol = module.get_elf_symbol_by_name(name, elf_file);
                    if let Ok(symbol) = symbol {
                        if !symbol.is_undefined() {
                            module_symbol.relocation_ex2(&self.backend, &symbol)?;
                        }
                    }
                }
                linux_module.resolved_symbol.clear();
            }
        }

        if so_name == "libc.so" {
            let malloc = module.find_symbol_by_name("malloc", false)?;
            let free = module.find_symbol_by_name("free", false)?;
            self.malloc = Some(malloc);
            self.free = Some(free);
            info!("Init malloc and free");
        }

        module.entry_point = elf_file.entry_point as u64;

        let module = Rc::new(UnsafeCell::new(module));

        if option_env!("SHOW_MODULES_INSERT_LOG").unwrap_or("") == "1" {
            println!("Insert module: {}", so_name);
        }

        self.modules.insert(so_name.clone(), module.clone());

        Ok(module)
    }

    fn resolve_symbol(
        &mut self,
        load_base: u64,
        symbol: &Option<ElfSymbol>,
        relocation_addr: &VMPointer<'a, T>,
        so_name: &str,
        needed_libraries: &IndexMap<String, RcUnsafeCell<LinuxModule<'a, T>>>,
        offset: u64,
        emulator: &AndroidEmulator<'a, T>,
        elf_file: &ElfFile
    ) -> anyhow::Result<ModuleSymbol> {
        if symbol.is_none() {
            return Ok(ModuleSymbol::new(so_name.to_string(), load_base as i64, None, relocation_addr.addr, so_name.to_string(), offset));
        }

        if let Some(symbol) = symbol {
            if !symbol.is_undefined() {
                if symbol.is_gnu_ifunc() {
                    let impl_addr = emulator.resolve_gnu_ifunc(load_base + symbol.value as u64);
                    return Ok(ModuleSymbol::new(
                        so_name.to_string(),
                        WEAK_BASE,
                        Some(symbol.clone()),
                        relocation_addr.addr,
                        so_name.to_string(),
                        impl_addr,
                    ));
                }
                let symbol_name = symbol.name(elf_file)?;

                let hash = tool::calculate_hash(&format!("{}#{}", so_name, symbol_name));

                if self.cache_hook.contains_key(&hash) {
                    let hook = self.cache_hook.get(&hash).unwrap();
                    return Ok(ModuleSymbol::new(so_name.to_string(), WEAK_BASE, Some(symbol.clone()), relocation_addr.addr, so_name.to_string(), *hook));
                }

                for hook in &self.hook_listeners {
                    let hook = hook.hook(emulator, so_name.to_string(), symbol_name.clone(), load_base + symbol.value as u64 + offset);
                    if hook > 0 {
                        self.cache_hook.insert(hash, hook);
                        return Ok(ModuleSymbol::new(so_name.to_string(), WEAK_BASE, Some(symbol.clone()), relocation_addr.addr, so_name.to_string(), hook));
                    }
                }

                return Ok(ModuleSymbol::new(so_name.to_string(), load_base as i64, Some(symbol.clone()), relocation_addr.addr, so_name.to_string(), offset));
            }

            let module = ModuleSymbol::new(so_name.to_string(), load_base as i64, Some(symbol.clone()), relocation_addr.addr, "".to_string(), offset);

            return module.resolve(emulator, needed_libraries, false, &self.hook_listeners, &mut self.cache_hook, elf_file);
        }

        Err(anyhow!("symbol is none"))
    }

    pub fn mem_map(&mut self, address: u64, size: usize, prot: u32, library_name: String, align: u64) -> Alignment {
        let alignment = align_addr(address, size as u64, align as i64);


        self.backend.mem_map(alignment.address, alignment.size, prot)
            .expect("mem_map failed");

        if self.memory_map.insert(alignment.address, MemoryMap::new(alignment.address, alignment.size, prot)).is_some() {
            warn!("mem_map replace exists memory map base=0x{:X}", alignment.address);
        }

        alignment
    }

    fn apply_relr(&self, load_base: u64, relr_vaddr: u64, relr_size: u32) -> anyhow::Result<()> {
        let table = load_base + relr_vaddr;
        let count = (relr_size as usize) / 8;
        let mut where_ptr: u64 = 0;
        for i in 0..count {
            let entry = self.backend.mem_read_u64(table + (i as u64) * 8)?;
            if entry & 1 == 0 {
                where_ptr = load_base + entry;
                let val = self.backend.mem_read_u64(where_ptr).unwrap_or(0).wrapping_add(load_base);
                self.backend.mem_write(where_ptr, &val.to_le_bytes())?;
                where_ptr += 8;
            } else {
                let mut bitmap = entry;
                let mut idx = 0u64;
                bitmap >>= 1;
                while bitmap != 0 {
                    if bitmap & 1 != 0 {
                        let loc = where_ptr + idx * 8;
                        let val = self.backend.mem_read_u64(loc).unwrap_or(0).wrapping_add(load_base);
                        self.backend.mem_write(loc, &val.to_le_bytes())?;
                    }
                    bitmap >>= 1;
                    idx += 1;
                }
                where_ptr += 8 * 63;
            }
        }
        Ok(())
    }

    pub fn add_hook_listeners(&mut self, listener: Box<dyn HookListener<'a, T>>) {
        self.hook_listeners.push(listener);
    }

    pub fn allocate_stack(&mut self, size: usize) -> VMPointer<'a, T> {
        self.set_stack_point(self.sp - size as u64);
        VMPointer::new(self.sp, size, self.backend.clone())
    }

    pub fn set_stack_point(&mut self, sp: u64) {
        if self.sp == 0 {
            self.stack_base = sp;
        }
        self.sp = sp;
        self.backend.reg_write(RegisterARM64::SP, sp)
            .expect("failed to set stack base");
    }

    pub fn write_stack_string(&mut self, string: String) -> anyhow::Result<VMPointer<'a, T>> {
        let size = align_size(string.bytes().len() + 1);
        let pointer = self.allocate_stack(size);
        pointer.write_c_string(string.as_str())?;
        Ok(pointer)
    }

    pub fn write_stack_bytes(&mut self, bytes: Bytes) -> anyhow::Result<VMPointer<'a, T>> {
        let size = align_size(bytes.len());
        let pointer = self.allocate_stack(size);
        pointer.write_bytes(bytes)?;
        Ok(pointer)
    }

    fn init_tls(&mut self, pid: u32, proc_name: String) -> anyhow::Result<(VMPointer<'a, T>, VMPointer<'a, T>)> {
        let thread = self.allocate_stack(0x400);
        let mut buf = BytesMut::new();
        buf.put_u64_le(0); // next pointer
        buf.put_u64_le(0); // prev pointer
        buf.put_u32_le(pid);
        thread.write_bytes(buf.freeze())?;

        let __stack_chk_guard = self.allocate_stack(8);
        let proc_name = self.write_stack_string(proc_name)?;

        let proc_name_ptr = self.allocate_stack(8);
        proc_name_ptr.write_u64(proc_name.addr)?;

        let auxv = self.allocate_stack(0x100);
        const AT_RANDOM: u64 = 25; // AT_RANDOM is a pointer to 16 bytes of randomness on the stack.
        auxv.write_u64_with_offset(0, AT_RANDOM)?;
        auxv.write_u64_with_offset(8, __stack_chk_guard.addr)?;
        const AT_PAGESZ: u64 = 6;
        auxv.write_u64_with_offset(8 * 2, AT_PAGESZ)?;
        auxv.write_u64_with_offset(8 * 3, PAGE_ALIGN as u64)?;
        const AT_HWCAP: u64 = 16;
        auxv.write_u64_with_offset(8 * 4, AT_HWCAP)?;
        auxv.write_u64_with_offset(8 * 5, crate::android::sdk::GUEST_HWCAP)?;
        auxv.write_u64_with_offset(8 * 6, 0)?;
        auxv.write_u64_with_offset(8 * 7, 0)?;

        let envs = vec![
            "ANDROID_DATA=/data",
            "ANDROID_ROOT=/system",
            "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
            "NO_ADDR_COMPAT_LAYOUT_FIXUP=1"
        ];
        let environ = self.allocate_stack(8 * (envs.len() + 1));
        let mut pointer = environ.share(0);
        for env in envs {
            let p = self.write_stack_string(env.to_string())?;
            pointer.write_u64(p.addr)?;
            pointer = pointer.share(8);
        }
        pointer.write_u64(0)?;

        let argv = self.allocate_stack(0x100);
        argv.write_u64_with_offset(8, proc_name_ptr.addr)?;
        argv.write_u64_with_offset(2 * 8, environ.addr)?;
        argv.write_u64_with_offset(3 * 8, auxv.addr)?;

        // TCB slots live at TPIDR+0. ELF static TLS is placed after them
        // (see `ELF_TLS_TPREL_BIAS`) so libc++ `.tbss` does not smash errno.
        let tls = self.allocate_stack(0x2000); // tls size
        //tls.write_u64_with_offset(0, 0x11_45_14).unwrap();
        tls.write_u64_with_offset(8, thread.addr).unwrap();
        let errno = tls.share(8 * 2);
        tls.write_u64_with_offset(8 * 3, argv.addr).unwrap();
        // TLS_SLOT_STACK_GUARD = 5. libc preinit copies this into __stack_chk_guard.
        const STACK_CANARY: u64 = 0xa5a5_a5a5_a5a5_a5a5;
        __stack_chk_guard.write_u64(STACK_CANARY)?;
        tls.write_u64_with_offset(8 * 5, STACK_CANARY).unwrap();

        self.backend.reg_write(RegisterARM64::TPIDR_EL0, tls.addr)
            .map_err(|e| anyhow!("init tls failed: {:?}", e))?;

        let mut sp = self.sp;
        sp &= !15;
        self.set_stack_point(sp);

        Ok((argv.share_with_size(8 * 2, 0), errno))
    }

    pub(crate) fn restore_thread_argv(&self) {
        let tls = VMPointer::new(self.backend.reg_read(RegisterARM64::TPIDR_EL0).unwrap(), 0, self.backend.clone());
        let argv = self.environ.share_with_size(-8 * 2, 0);
        tls.write_u64_with_offset(8 * 3, argv.addr).unwrap();
    }
}

/// Replace PAC/BTI HINT encodings with `nop`. Dynarmic has no PAC/BTI and
/// hits `InterpreterFallback` → host abort on Android 16 CRT (`paciasp`, `bti`).
fn neutralize_pac_bti<T: Clone>(backend: &Backend<T>, addr: u64, size: usize) {
    const NOP: u32 = 0xd503201f;
    const HINT_MASK: u32 = 0xfffff01f;
    let size = size & !3;
    if size == 0 {
        return;
    }
    let mut buf = vec![0u8; size];
    if backend.mem_read(addr, &mut buf).is_err() {
        return;
    }
    let mut n = 0u32;
    for i in (0..size).step_by(4) {
        let insn = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        if insn & HINT_MASK != NOP {
            continue;
        }
        let crm = (insn >> 8) & 0xf;
        // CRm 2/3 = PAC/AUT, CRm 4 = BTI
        if crm >= 2 && crm <= 4 && insn != NOP {
            buf[i..i + 4].copy_from_slice(&NOP.to_le_bytes());
            n += 1;
        }
    }
    if n > 0 {
        let _ = backend.mem_write(addr, &buf);
        info!("neutralized {n} PAC/BTI hints at 0x{addr:X}");
    }
}

fn get_base_name(file_name: &str) -> String {
    // libfekit,so -> libfekit
    let mut base_name = file_name.to_string();
    if let Some(pos) = base_name.find('.') {
        base_name = base_name[..pos].to_string();
    }
    base_name
}
