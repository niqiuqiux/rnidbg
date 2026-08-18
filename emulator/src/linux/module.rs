use crate::backend::Backend;
use crate::elf::dynamic_struct::ElfDynamicStructure;
use crate::elf::memorized_object::MemoizedObject;
use crate::elf::parser::ElfFile;
use crate::elf::pt::{ArmExIdx, GnuEhFrameHeader};
use crate::elf::section::ElfSection;
use crate::elf::symbol::ElfSymbol;
use crate::elf::symbol_structure::SymbolLocator;
use crate::emulator::{AndroidEmulator, RcUnsafeCell, VMPointer};
use crate::linux::init_fun::{InitFunction, InitFunctionTrait};
use crate::linux::symbol::{LinuxSymbol, ModuleSymbol};
use crate::linux::PAGE_ALIGN;
use crate::memory::ModuleMemRegion;
use crate::tool::align_addr;
use anyhow::anyhow;
use indexmap::IndexMap;
use log::info;
use std::cell::UnsafeCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

pub struct LinuxModule<'a, T: Clone> {
    pub name: String,
    pub base: u64,
    pub size: usize,
    pub(crate) needed_libraries: IndexMap<String, RcUnsafeCell<LinuxModule<'a, T>>>,
    pub regions: Vec<ModuleMemRegion>,
    pub ref_cnt: Arc<AtomicU32>,
    /*
     * Elf information
     */
    pub entry_point: u64,

    pub path_pointer: VMPointer<'a, T>,

    /*
    LinuxModule
     */
    pub hook_map: HashMap<String, u64>,
    pub(crate) dynsym: Option<SymbolLocator>,
    pub virtual_base: u64,
    pub(crate) unresolved_symbol: Vec<ModuleSymbol>,
    pub(crate) resolved_symbol: IndexMap<String, ModuleSymbol>,
    pub(crate) init_function_list: VecDeque<InitFunction<'a, T>>,
    pub(crate) arm_ex_idx: Option<MemoizedObject<ArmExIdx>>,
    pub(crate) eh_frame_header: Option<MemoizedObject<GnuEhFrameHeader>>,
    pub(crate) symbol_table_section: Option<ElfSection>,
    pub(crate) dynamic_structure: Option<ElfDynamicStructure>,
    pub(crate) elf_file: Option<Rc<UnsafeCell<ElfFile>>>,
}

impl<'a, T: Clone> LinuxModule<'a, T> {
    pub(crate) fn new(
        virtual_base: u64,
        base: u64,
        size: usize,
        name: String,
        dynsym: Option<SymbolLocator>,
        unresolved_symbol: Vec<ModuleSymbol>,
        init_function_list: VecDeque<InitFunction<'a, T>>,
        needed_libraries: IndexMap<String, RcUnsafeCell<LinuxModule<'a, T>>>,
        regions: Vec<ModuleMemRegion>,
        arm_ex_idx: Option<MemoizedObject<ArmExIdx>>,
        eh_frame_header: Option<MemoizedObject<GnuEhFrameHeader>>,
        symbol_table_section: Option<ElfSection>,
        elf_file: Option<Rc<UnsafeCell<ElfFile>>>,
        dynamic_structure: Option<ElfDynamicStructure>,
    ) -> Self {
        Self {
            virtual_base,
            dynsym,
            unresolved_symbol,
            init_function_list,
            arm_ex_idx,
            symbol_table_section,
            dynamic_structure,
            base,
            size,
            name,
            needed_libraries,
            regions,
            ref_cnt: Arc::new(AtomicU32::new(0)),
            entry_point: 0,
            path_pointer: VMPointer::null(),
            eh_frame_header,
            elf_file,
            hook_map: HashMap::new(),
            resolved_symbol: IndexMap::new(),
        }
    }

    pub fn find_symbol_by_closest_addr(&self, addr: u64) -> anyhow::Result<LinuxSymbol> {
        if let Some(dynsym) = self.dynsym.as_ref() {
            let so_addr = addr.overflowing_sub(self.base);
            if so_addr.1 {
                return Err(anyhow!(
                    "Failed to find symbol by closest addr: 0x{:X}",
                    addr
                ));
            }
            let elf_symbol = match dynsym {
                SymbolLocator::Section(sc) => sc.get_elf_symbol_by_addr(so_addr.0),
                SymbolLocator::SymbolStructure(ss) => ss.get_elf_symbol_by_addr(so_addr.0),
            };
            let elf_file = unsafe { &*self.elf_file.as_ref().unwrap().get() };
            let mut symbol = if let Ok(elf_symbol) = elf_symbol {
                LinuxSymbol::new(
                    elf_symbol.name(elf_file)?,
                    elf_symbol,
                    self.base,
                    self.name.clone(),
                )
                .into()
            } else {
                None
            };
            let entry = self.base + self.entry_point;
            if addr >= entry && symbol.is_some() && entry > symbol.as_ref().unwrap().address() {
                symbol = Some(LinuxSymbol::new(
                    "start".to_string(),
                    symbol.unwrap().symbol,
                    self.base,
                    self.name.clone(),
                ));
            }

            if let Some(symbol) = symbol {
                return Ok(symbol);
            }
        }
        Err(anyhow!(
            "Failed to find symbol by closest addr: 0x{:X}",
            addr
        ))
    }

    pub fn find_symbol_by_name(&self, name: &str, with_dep: bool) -> anyhow::Result<LinuxSymbol> {
        if let Some(dynsym) = self.dynsym.as_ref() {
            let elf_file = unsafe { &*self.elf_file.as_ref().unwrap().get() };
            let elf_symbol = match dynsym {
                SymbolLocator::Section(sec) => sec.get_elf_symbol_by_name(name, elf_file),
                SymbolLocator::SymbolStructure(ss) => ss.get_elf_symbol_by_name(name, elf_file),
            };
            if let Ok(elf_symbol) = elf_symbol {
                return Ok(LinuxSymbol::new(
                    name.to_string(),
                    elf_symbol,
                    self.base,
                    self.name.clone(),
                ));
            }

            if with_dep {
                for (_, lib) in &self.needed_libraries {
                    let module = unsafe { &*lib.get() };
                    let symbol = module.find_symbol_by_name(name, with_dep);
                    if let Ok(symbol) = symbol {
                        return Ok(symbol);
                    }
                }
            }
        }
        Err(anyhow!("Failed to find symbol by name: {}", name))
    }

    pub fn get_elf_symbol_by_name(
        &self,
        name: &str,
        elf_file: &ElfFile,
    ) -> anyhow::Result<ElfSymbol> {
        if let Some(dynsym) = &self.dynsym {
            let symbol = match dynsym {
                SymbolLocator::Section(sec) => sec.get_elf_symbol_by_name(name, elf_file),
                SymbolLocator::SymbolStructure(ss) => ss.get_elf_symbol_by_name(name, elf_file),
            };
            return symbol;
        }

        Err(anyhow!("dynsym is none"))
    }

    pub fn create_virtual_module(name: String, symbol: HashMap<String, u64>) -> Self {
        if symbol.is_empty() {
            panic!("symbol is empty!")
        }
        let mut list = symbol.iter().map(|(k, v)| v.clone()).collect::<Vec<_>>();
        list.sort();

        let first = list.first().unwrap().clone();
        let last = list.last().unwrap().clone();

        let alignment = align_addr(first, last - first, PAGE_ALIGN as i64);
        let base = alignment.address;
        let size = alignment.size;

        info!(
            "createVirtualModule first=0x{:X} , last=0x{:X}, base=0x{:X}, size=0x{:X}",
            first, last, base, size
        );

        let module = LinuxModule::new(
            base,
            base,
            size,
            name,
            None,
            vec![],
            VecDeque::new(),
            IndexMap::new(),
            vec![],
            None,
            None,
            None,
            None,
            None,
        );

        module
    }

    pub fn path(&self, emulator: &AndroidEmulator<T>) -> String {
        if self.name == "liblog.so" {
            return "/system/lib64/liblog.so".to_string();
        } else if self.name == "libc++.so" {
            return "/system/lib64/libc++.so".to_string();
        } else if self.name == "libc.so" {
            return "/system/lib64/libc.so".to_string();
        } else if self.name == "libm.so" {
            return "/system/lib64/libm.so".to_string();
        } else if self.name == "libdl.so" {
            return "/system/lib64/libdl.so".to_string();
        } else if self.name == "libstdc++.so" {
            return "/system/lib64/libstdc++.so".to_string();
        } else if self.name == "libz.so" {
            return "/system/lib64/libz.so".to_string();
        } else if self.name == "libandroid.so" {
            return "/system/lib64/libandroid.so".to_string();
        }
        let package_name = emulator
            .inner_mut()
            .proc_name
            .split(":")
            .next()
            .unwrap_or("");
        format!(
            "/data/app/~~YuanShenZhenChaoHaoWan/{}-0/lib/arm64/{}",
            package_name, self.name
        )
    }

    /// unidbg `LinuxModule.callEntry`: build argc/argv/envp/auxv and jump to `e_entry`.
    pub fn call_entry(&self, emulator: &AndroidEmulator<'a, T>, args: &[&str]) -> anyhow::Result<i32> {
        if self.entry_point == 0 {
            return Err(anyhow!("Invalid entry point"));
        }

        emulator.set_exec_path(self.path(emulator));
        let proc_name = emulator.inner_mut().proc_name.clone();

        let memory = &mut emulator.inner_mut().memory;
        let _stack_mark = memory.allocate_stack(0);

        let mut argv_ptrs = Vec::new();
        argv_ptrs.push(memory.write_stack_string(proc_name)?);
        for arg in args {
            argv_ptrs.push(memory.write_stack_string((*arg).to_string())?);
        }
        let argc = argv_ptrs.len() as i32;

        if argc % 2 != 0 {
            memory.allocate_stack(8);
        }

        let random = memory.allocate_stack(16);
        random.write_u64(0xa5a5_a5a5_a5a5_a5a5)?;
        random.write_u64_with_offset(8, 0x5a5a_5a5a_5a5a_5a5a)?;

        let (phoff, phentsize, phnum) = if let Some(cell) = &self.elf_file {
            let elf = unsafe { &*cell.get() };
            (elf.ph_offset as u64, elf.ph_entry_size as u64, elf.num_ph as u64)
        } else {
            (0, 56, 0)
        };
        const AT_NULL: u64 = 0;
        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_BASE: u64 = 7;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_HWCAP: u64 = 16;
        const AT_SECURE: u64 = 23;
        const AT_RANDOM: u64 = 25;
        let auxv_pairs: [(u64, u64); 14] = [
            (AT_PHDR, self.base + phoff),
            (AT_PHENT, phentsize),
            (AT_PHNUM, phnum),
            (AT_PAGESZ, PAGE_ALIGN as u64),
            (AT_BASE, 0),
            (AT_ENTRY, self.base + self.entry_point),
            (AT_UID, 10261),
            (AT_EUID, 10261),
            (AT_GID, 10261),
            (AT_EGID, 10261),
            (AT_HWCAP, crate::android::sdk::GUEST_HWCAP),
            (AT_SECURE, 0),
            (AT_RANDOM, random.addr),
            (AT_NULL, 0),
        ];
        for (ty, val) in auxv_pairs.iter().rev() {
            let slot = memory.allocate_stack(16);
            slot.write_u64(*ty)?;
            slot.write_u64_with_offset(8, *val)?;
        }

        let env_strings = [
            "ANDROID_DATA=/data",
            "ANDROID_ROOT=/system",
            "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
        ];
        let mut env_ptrs = Vec::new();
        for e in env_strings {
            env_ptrs.push(memory.write_stack_string(e.to_string())?);
        }
        memory.allocate_stack(8).write_u64(0)?;
        for ptr in env_ptrs.iter().rev() {
            memory.allocate_stack(8).write_u64(ptr.addr)?;
        }

        memory.allocate_stack(8).write_u64(0)?;
        for ptr in argv_ptrs.iter().rev() {
            memory.allocate_stack(8).write_u64(ptr.addr)?;
        }

        let kab = memory.allocate_stack(8);
        kab.write_i32_with_offset(0, argc)?;

        let sp = kab.addr;
        let entry = self.base + self.entry_point;
        let ret = emulator.e_entry(entry, sp);
        if let Some(status) = emulator.last_exit_status() {
            return Ok(status);
        }
        match ret {
            Some(code) => Ok(code as i32),
            None => {
                log::warn!("process stopped without exit_group");
                Ok(1)
            }
        }
    }

    pub fn unload(&self, unicorn: &Backend<T>) -> anyhow::Result<()> {
        for region in &self.regions {
            unicorn
                .mem_unmap(region.begin, (region.end - region.begin) as usize)
                .map_err(|e| anyhow!("LinuxModule unload, but failed to mem_unmap: {:?}", e))?;
        }
        Ok(())
    }
}

impl<'a, T: Clone> LinuxModule<'a, T> {
    pub(crate) fn call_init_functions(
        &mut self,
        must_call_init: bool,
        emulator: &AndroidEmulator<'a, T>,
    ) -> anyhow::Result<()> {
        if !must_call_init && !self.unresolved_symbol.is_empty() {
            return Ok(());
        }

        //let mut called_functions = vec![];

        loop {
            let init_function = self.init_function_list.pop_front();

            if let Some(init_function) = init_function {
                match init_function {
                    InitFunction::ABSOLUTE(absolute) => {
                        if option_env!("SHOW_INIT_FUNC_CALL").unwrap_or("") == "1" {
                            let start_time = std::time::Instant::now();
                            let mut address = absolute.ptr.read_u64_with_offset(0)?;
                            if address == 0 {
                                address = absolute.addr;
                            }

                            /*if called_functions.contains(&address) {
                                error!("[{}] Already CallInitFunction: address=0x{:X}, base=0x{:X}, offset=0x{:X}, start={:?}", self.name, address, absolute.load_base, address - absolute.load_base, start_time);
                                panic!()
                            } else {
                                called_functions.push(address);
                            }*/

                            println!("[{}] CallInitFunctionStart: address=0x{:X}, base=0x{:X}, offset=0x{:X}, start={:?}", self.name, address, absolute.load_base, address - absolute.load_base, start_time);

                            let offset = address - absolute.load_base;
                            //if offset == 0x1aa74 && self.name == "libc.so"  {
                            //    continue
                            //}

                            let ret = absolute.call(emulator.clone())?;
                            let cost = start_time.elapsed().as_millis();
                            println!("[{}] CallInitFunctionEnd: address=0x{:X}, base=0x{:X}, offset=0x{:X}, ret={:X}, cost={}ms", self.name, address, absolute.load_base, offset, ret, cost);
                        } else {
                            let ret = absolute.call(emulator.clone())?;
                            let _ = ret;
                            if emulator.last_exit_status().is_some() {
                                return Ok(());
                            }
                        }
                    }
                    InitFunction::LINUX(linux) => {
                        if option_env!("SHOW_INIT_FUNC_CALL").unwrap_or("") == "1" {
                            let start_time = std::time::Instant::now();
                            let address = linux.addr;

                            println!(
                                "[{}] CallInitFunctionStart base=0x{:X}, offset=0x{:X}, start={:?}",
                                self.name,
                                linux.load_base,
                                address - linux.load_base,
                                start_time
                            );

                            /*if called_functions.contains(&address) {
                                error!("[{}] ALREADY CallInitFunction: base=0x{:X}, offset=0x{:X}, start={:?}", self.name, linux.load_base, address - linux.load_base, start_time);
                                panic!()
                            } else {
                                called_functions.push(address);
                            }*/

                            let ret = linux.call(emulator.clone())?;
                            let cost = start_time.elapsed().as_millis();
                            println!("[{}] CallInitFunctionEnd: base=0x{:X}, offset=0x{:X}, ret={:X}, cost={}ms", self.name, linux.load_base, address - linux.load_base, ret, cost);
                        } else {
                            let ret = linux.call(emulator.clone())?;
                            let _ = ret;
                            if emulator.last_exit_status().is_some() {
                                return Ok(());
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }

        Ok(())
    }
}
