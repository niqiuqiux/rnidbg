use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use log::{debug, info, warn};
use crate::android::sdk::ANDROID_SDK;
use crate::backend::{Backend, Permission, RegisterARM64};
use crate::emulator::{AndroidEmulator, POST_CALLBACK_SYSCALL_NUMBER, VMPointer};
use crate::keystone;
use crate::linux::errno::Errno;
use crate::linux::structs::DlInfo;
use crate::memory::svc_memory::{Arm64Svc, assemble_svc, HookListener, SvcMemory, SvcCallResult};
use crate::memory::svc_memory::SvcCallResult::{FUCK, RET, VOID};

/// Writable page for the virtual `libc_shared_globals` block.
/// Device `ld-android.so` is a 4-byte `brk` stub; the real object lives in linker64
/// (`__dl__ZZ21__libc_shared_globalsvE7globals`, 1760 bytes). libc preinit writes
/// `tls_modules.generation` at +0x478, `generation_libc_so` at +0x480, and
/// `set_target_sdk_version_hook` at +0x628.
const LOADER_SHARED_GLOBALS_ADDR: u64 = 0xfffd0000;
const LOADER_SHARED_GLOBALS_SIZE: usize = 0x1000;

struct DlIteratePhdr;
struct DlClose<'a, T: Clone>(pub VMPointer<'a, T>);
struct DlError<'a, T: Clone>(pub VMPointer<'a, T>);
struct DlOpen<'a, T: Clone>(pub VMPointer<'a, T>);
struct DlAddr;
struct DlSym;
struct DlUnwindFindExidx;

pub struct ArmLD64<'a, T: Clone> {
    error: VMPointer<'a, T>,
    shared_globals: u64,
}

impl<'a, T: Clone> ArmLD64<'a, T> {
    pub fn new(
        svc_memory: &mut SvcMemory<'a, T>,
        backend: &Backend<'a, T>,
    ) -> anyhow::Result<ArmLD64<'a, T>> {
        backend
            .mem_map(
                LOADER_SHARED_GLOBALS_ADDR,
                LOADER_SHARED_GLOBALS_SIZE,
                (Permission::READ | Permission::WRITE).bits(),
            )
            .map_err(|e| anyhow!("map libc_shared_globals failed: {:?}", e))?;
        // Low page: API 36 libc will ldrb through NULL+off if auxv/globals are unset.
        // Keep it RW and zeroed so constructors fail soft instead of aborting the host.
        // Cover NULL and unrelocated low addresses (IFUNC args, stray .rodata).
        if backend
            .mem_map(0, 0x10000, (Permission::READ | Permission::WRITE).bits())
            .is_ok()
        {
            let _ = backend.mem_write(0, &[0u8; 0x1000]);
        }
        let shared = VMPointer::new(
            LOADER_SHARED_GLOBALS_ADDR,
            LOADER_SHARED_GLOBALS_SIZE,
            backend.clone(),
        );
        shared.write_buf(vec![0u8; LOADER_SHARED_GLOBALS_SIZE])?;
        populate_shared_globals(&shared)?;

        let pointer = svc_memory.allocate(0x80, "Dlfcn.error");
        pointer.write_buf(vec![0u8; 0x80])?;
        Ok(ArmLD64 {
            error: pointer,
            shared_globals: LOADER_SHARED_GLOBALS_ADDR,
        })
    }

    fn hook_loader(&self, emu: &AndroidEmulator<'a, T>, symbol_name: &str, old: u64) -> u64 {
        info!("[ld-android] link {}, old=0x{:X}", symbol_name, old);
        let svc = &mut emu.inner_mut().svc_memory;
        match symbol_name {
            "__loader_shared_globals" => svc.register_svc(Box::new(LoaderConst {
                name: "LoaderSharedGlobals",
                ret: self.shared_globals as i64,
            })),
            "__loader_android_get_application_target_sdk_version" => {
                svc.register_svc(Box::new(LoaderConst {
                    name: "LoaderGetTargetSdk",
                    ret: ANDROID_SDK as i64,
                }))
            }
            "__loader_dlopen" | "__loader_android_dlopen_ext" => {
                svc.register_svc(Box::new(DlOpen(self.error.clone())))
            }
            "__loader_dlerror" => svc.register_svc(Box::new(DlError(self.error.clone()))),
            "__loader_dlclose" => svc.register_svc(Box::new(DlClose(self.error.clone()))),
            "__loader_dlsym" | "__loader_dlvsym" => svc.register_svc(Box::new(DlSym)),
            "__loader_dladdr" => svc.register_svc(Box::new(DlAddr)),
            "__loader_dl_iterate_phdr" => svc.register_svc(Box::new(DlIteratePhdr)),
            _ => {
                warn!("[ld-android] stub {} at 0x{:X} -> 0", symbol_name, old);
                svc.register_svc(Box::new(LoaderConst {
                    name: "LoaderStub",
                    ret: 0,
                }))
            }
        }
    }
}

impl<'a, T: Clone> HookListener<'a, T> for ArmLD64<'a, T> {
    fn hook(&self, emu: &AndroidEmulator<'a, T>, lib_name: String, symbol_name: String, old: u64) -> u64 {
        if lib_name == "ld-android.so" || symbol_name.starts_with("__loader_") {
            return self.hook_loader(emu, symbol_name.as_str(), old);
        }
        if lib_name != "libdl.so" {
            return 0;
        }
        info!("[libdl.so] link {}, old=0x{:X}", symbol_name, old);
        let svc = &mut emu.inner_mut().svc_memory;
        match symbol_name.as_str() {
            "dl_iterate_phdr" => svc.register_svc(Box::new(DlIteratePhdr)) ,
            "dlerror" => svc.register_svc(Box::new(DlError(self.error.clone()))),
            "dlclose" => svc.register_svc(Box::new(DlClose(self.error.clone()))),
            "dlopen" => svc.register_svc(Box::new(DlOpen(self.error.clone()))),
            "dladdr" => svc.register_svc(Box::new(DlAddr)),
            "dlsym" | "dlvsym" => svc.register_svc(Box::new(DlSym)),
            "dl_unwind_find_exidx" => svc.register_svc(Box::new(DlUnwindFindExidx)),
            "android_dlopen_ext" => svc.register_svc(Box::new(DlOpen(self.error.clone()))),
            "android_get_application_target_sdk_version" => svc.register_svc(Box::new(LoaderConst {
                name: "GetTargetSdk",
                ret: ANDROID_SDK as i64,
            })),
            _ => {
                info!("[libdl.so] leave {} at 0x{:X} unhooked", symbol_name, old);
                0
            }
        }
    }
}

/// Layout of the in-page `libc_shared_globals` block (API 36 / Android 16).
/// `getauxval` does `ldr x8, [globals, #0x418]; ldr x9, [x8]`.
const OFF_AUXV: u64 = 0x418;
const OFF_TLS_GENERATION: u64 = 0x478;
const AUXV_TABLE_OFF: u64 = 0x800;
const AT_RANDOM_OFF: u64 = 0x8c0;
const AT_PLATFORM_OFF: u64 = 0x8d0;

fn populate_shared_globals<T: Clone>(shared: &VMPointer<T>) -> anyhow::Result<()> {
    let base = shared.addr;
    // AT_RANDOM payload (16 bytes) and AT_PLATFORM string live in the same page.
    shared.write_bytes_with_offset(AT_RANDOM_OFF, bytes::Bytes::from_static(&[
        0xa5, 0x5a, 0x3c, 0xc3, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9,
    ]))?;
    shared.share(AT_PLATFORM_OFF as i64).write_c_string("aarch64")?;

    // Elf64_auxv_t[] used by getauxval.
    let auxv = base + AUXV_TABLE_OFF;
    const AT_PAGESZ: u64 = 6;
    const AT_PLATFORM: u64 = 15;
    const AT_HWCAP: u64 = 16;
    const AT_RANDOM: u64 = 25;
    const AT_SECURE: u64 = 23;
    let entries: [(u64, u64); 6] = [
        (AT_PAGESZ, 0x1000),
        (AT_HWCAP, crate::android::sdk::GUEST_HWCAP),
        (AT_SECURE, 0),
        (AT_RANDOM, base + AT_RANDOM_OFF),
        (AT_PLATFORM, base + AT_PLATFORM_OFF),
        (0, 0),
    ];
    for (i, (ty, val)) in entries.iter().enumerate() {
        let off = AUXV_TABLE_OFF + (i as u64) * 16;
        shared.write_u64_with_offset(off, *ty)?;
        shared.write_u64_with_offset(off + 8, *val)?;
    }
    shared.write_u64_with_offset(OFF_AUXV, auxv)?;
    // tls_modules.generation starts at 1 so libc's copy is non-zero.
    shared.write_u64_with_offset(OFF_TLS_GENERATION, 1)?;
    Ok(())
}

struct LoaderConst {
    name: &'static str,
    ret: i64,
}

impl<T: Clone> Arm64Svc<T> for LoaderConst {
    fn name(&self) -> &str {
        self.name
    }

    fn handle(&self, _emu: &AndroidEmulator<T>) -> SvcCallResult {
        RET(self.ret)
    }
}

impl<T: Clone> Arm64Svc<T> for DlIteratePhdr {
    fn name(&self) -> &str {
        "DlIteratePhdr"
    }

    fn on_register(&self, svc: &mut SvcMemory<T>, number: u32) -> u64 {
        let code = [
            "sub sp, sp, #0x10",
            "stp x29, x30, [sp]",
            &format!("svc #0x{:x}", number),
            "ldr x13, [sp]", // x13 == callback 0xc
            "add sp, sp, #0x8", // pop callback
            "cmp x13, #0", // if callback == 0
            "b.eq #0x58", // 0x58
            "ldr x0, [sp]", // x0 == ptr
            "add sp, sp, #0x8", // pop ptr
            "ldr x1, [sp]", // x1 == size
            "add sp, sp, #0x8", // pop size
            "ldr x2, [sp]", // x2 == data
            "add sp, sp, #0x8", // pop data
            "blr x13", // callback(ptr, size, data)
                        // int (*callback)(struct dl_phdr_info *info,
                        //        size_t size, void *data)
            "cmp x0, #0", // if callback return 0
            "b.eq #0xc", // loop
            "ldr x13, [sp]", // 0x40
            "add sp, sp, #0x8",
            "cmp x13, #0",
            "b.eq #0x58", // 0x58
            "add sp, sp, #0x18",
            "b 0x40",
            "mov x8, #0", // 0x58
            &format!("mov x12, #0x{:x}", number),
            &format!("mov x16, #0x{:x}", POST_CALLBACK_SYSCALL_NUMBER),
            "svc #0",
            "ldp x29, x30, [sp]",
            "add sp, sp, #0x10",
            "ret"
        ];
        let code = code.join("\n");
        let code = keystone::assemble_no_check(&code);
        let pointer = svc.allocate(code.len(), "DlIteratePhdr");
        pointer.write_buf(code)
            .expect("try register svc");
        info!("DlIteratePhdr: pointer={:X}", pointer.addr);
        pointer.addr
    }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let cb = emu.backend.reg_read(RegisterARM64::X0).unwrap();
        let data = emu.backend.reg_read(RegisterARM64::X1).unwrap();

        let mut modules = emu.inner_mut()
            .memory
            .modules
            .iter()
            .filter(|(name, module)| {
                unsafe { (&*module.get()).elf_file.is_some() }
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(a, b)| b.clone())
            .rev()
            .collect::<Vec<_>>();

        let mut modules = modules.iter().map(|module_cell| {
            let module = unsafe { &mut *module_cell.get() };
            let elf_file = unsafe { &*module.elf_file.as_ref().unwrap().get() };
            (
                module.path(emu),
                module.base,
                module.base + elf_file.ph_offset as u64,
                elf_file.num_ph,
            )
        }).collect::<Vec<_>>();

        modules.push(("/apex/com.android.art/lib64/libart.so".to_string(), 0, 0, 0));

        let size = 64;
        let modules_len = modules.len();

        let Ok(mut ptr) = emu.falloc(size * modules_len, true) else {
            return FUCK(anyhow!("unable to alloc memory for DlIteratePhdr"))
        };
        let sp = match emu.backend.reg_read(RegisterARM64::SP)
            .map_err(|e| anyhow!("failed to read SP: {:?}", e)) {
            Ok(sp) => sp,
            Err(e) => return FUCK(e)
        };

        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            debug!("DlIteratePhdr cb={:X}, data={:X}, size={}, sp={:X}", cb, data, modules_len, sp);
        }

        let sp = VMPointer::new(sp, 0, emu.backend.clone());
        let mut sp = sp.share(-8);
        sp.write_u64(0).unwrap(); // NULL-terminated

        for (name, vaddr, phdr, phnum) in modules {
            info!("DlIteratePhdr: name={}, vaddr={:X}, phdr={:X}, phnum={}", name, vaddr, phdr, phnum);

            let dlpi_name = match emu.falloc(name.len() + 1, true) {
                Ok(p) => p,
                Err(e) => return FUCK(e)
            };
            dlpi_name.write_c_string(name.as_str()).unwrap();
            ptr.write_u64_with_offset(0, vaddr).unwrap();
            ptr.write_u64_with_offset(8, dlpi_name.addr).unwrap();
            ptr.write_u64_with_offset(16, phdr as u64).unwrap();
            ptr.write_u16_with_offset(24, phnum as u16).unwrap();

            sp = sp.share(-8);
            sp.write_u64(data).unwrap();

            sp = sp.share(-8);
            sp.write_u64(size as u64).unwrap();

            sp = sp.share(-8);
            sp.write_u64(ptr.addr).unwrap();

            sp = sp.share(-8);
            sp.write_u64(cb).unwrap();

            ptr = ptr.share(size as i64);
        }

        emu.backend.reg_write(RegisterARM64::SP, sp.addr)
            .map_err(|e| anyhow!("failed to write SP: {:?}", e)).unwrap();

       VOID
    }

    fn on_post_callback(&self, emu: &AndroidEmulator<T>) -> u64 {
        0
    }
}

impl<T: Clone> Arm64Svc<T> for DlError<'_, T> {
    fn name(&self) -> &str {
        "DlError"
    }

    fn handle(&self, _emu: &AndroidEmulator<T>) -> SvcCallResult {
        RET(self.0.addr as i64)
    }
}

impl<T: Clone> Arm64Svc<T> for DlClose<'_, T> {
    fn name(&self) -> &str {
        "DlClose"
    }

    fn handle(&self, _emu: &AndroidEmulator<T>) -> SvcCallResult {
        RET(0)
    }
}

impl<T: Clone> Arm64Svc<T> for DlOpen<'_, T> {
    fn name(&self) -> &str {
        "DlOpen"
    }

    fn on_register(&self, svc: &mut SvcMemory<T>, number: u32) -> u64 {
        let mut buf = BytesMut::new();
        buf.put_u32_le(0xd10043ff);// "sub sp, sp, #0x10"
        buf.put_u32_le(0xa9007bfd);// "stp x29, x30, [sp]"
        buf.put_u32_le(assemble_svc(number));// "svc #0x" + Integer.toHexString(svcNumber)
        buf.put_u32_le(0xf94003ed);// "ldr x13, [sp]"
        buf.put_u32_le(0x910023ff);// "add sp, sp, #0x8", manipulated stack in dlopen
        buf.put_u32_le(0xf10001bf);// "cmp x13, #0"
        buf.put_u32_le(0x54000060);// "b.eq #0x24"
        buf.put_u32_le(0x10ffff9e);// "adr lr, #-0xf", jump to ldr x13, [sp]
        buf.put_u32_le(0xd61f01a0);// "br x13", call init array // "b.eq #0x24" to here
        buf.put_u32_le(0xf94003e0);// "ldr x0, [sp]", with return address
        buf.put_u32_le(0x910023ff);// "add sp, sp, #0x8"
        buf.put_u32_le(0xa9407bfd);// "ldp x29, x30, [sp]"
        buf.put_u32_le(0x910043ff);// "add sp, sp, #0x10"
        buf.put_u32_le(0xd65f03c0);// "ret"
        let pointer = svc.allocate(buf.len(), "dlopen");
        pointer.write_bytes(buf.freeze())
            .expect("try register svc failed");
        pointer.addr
    }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let file_name_ptr = VMPointer::new(emu.backend.reg_read(RegisterARM64::X0).unwrap(), 0, emu.backend.clone());

        let flags = emu.backend.reg_read(RegisterARM64::X1).unwrap();
        let file_name = file_name_ptr.read_string().unwrap();

        let pointer = VMPointer::new(emu.backend.reg_read(RegisterARM64::SP).unwrap(), 0, emu.backend.clone());
        let pointer = pointer.share_with_size(-8, 0); // ret

        if !file_name.is_ascii() {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                debug!("syscall dlopen(file_name=hex::decode({}), flags=0x{:X}) => 0", hex::encode(file_name.as_bytes()), flags);
            }

            pointer.write_u64(0).unwrap(); // dlopen函数调用返回值
            let pointer = pointer.share_with_size(-8, 0);
            pointer.write_u64(0).unwrap();
            emu.set_errno(Errno::ENOENT.as_i32()).unwrap();
            emu.backend.reg_write(RegisterARM64::SP, pointer.addr).unwrap();

            return RET(0)
        } else {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                debug!("syscall dlopen(file_name={}, flags=0x{:X})", file_name, flags);
            }
        }

        if file_name == "libnetd_client.so" || file_name.ends_with("libnetd_client.so") {
            pointer.write_u64(0).unwrap(); // dlopen函数调用返回值
            let pointer = pointer.share_with_size(-8, 0);
            pointer.write_u64(0).unwrap();
            emu.backend.reg_write(RegisterARM64::SP, pointer.addr).unwrap();
            return RET(0)
        }

        warn!("dlopen not implemented: {} flags=0x{:X}", file_name, flags);
        let _ = self.0.write_c_string(&format!("dlopen failed: {}", file_name));
        pointer.write_u64(0).unwrap();
        let pointer = pointer.share_with_size(-8, 0);
        pointer.write_u64(0).unwrap();
        let _ = emu.set_errno(Errno::ENOENT.as_i32());
        emu.backend.reg_write(RegisterARM64::SP, pointer.addr).unwrap();
        RET(0)
    }
}

impl<T: Clone> Arm64Svc<T> for DlAddr {
    fn name(&self) -> &str {
        "DlAddr"
    }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let addr = emu.backend.reg_read(RegisterARM64::X0).unwrap();
        let info_ptr = emu.backend.reg_read(RegisterARM64::X1).unwrap();

        let module = emu.inner_mut().memory.find_module_by_address(addr);
        if let Some(module) = module {
            let module = unsafe { &*module.get() };

            const INFO_SIZE: usize = size_of::<DlInfo>();
            let symbol = module.find_symbol_by_closest_addr(addr);
            return if let Ok(symbol) = symbol {
                let path = &module.path(emu);
                //let path = path.split('/').last().unwrap();
                let path_ptr = emu.falloc(path.len() + 1 + symbol.name.len() + 1, true).unwrap();
                path_ptr.write_c_string(path).unwrap();
                let sname_ptr = path_ptr.share((path.len() + 1) as i64);
                sname_ptr.write_c_string(symbol.name.as_str()).unwrap();

                let mut buffer = [0u8; INFO_SIZE];
                let info = unsafe { &mut *(buffer.as_mut_ptr() as *mut DlInfo) };
                info.dli_fname = path_ptr.addr;
                info.dli_fbase = module.virtual_base;
                info.dli_sname = sname_ptr.addr;
                info.dli_saddr = symbol.address();

                emu.backend.mem_write(info_ptr, &buffer).unwrap();

                if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                    debug!("syscall dladdr(addr=0x{:X}, info_ptr=0x{:X}) => Module(name={}, function)", addr, info_ptr, module.name);
                }

                RET(1)
            } else {
                let entry_point = module.entry_point;
                let path = module.path(emu);
                let path_ptr = emu.malloc(path.len() + 1 + 6, false).unwrap().pointer;
                path_ptr.write_c_string(path.as_str()).unwrap();
                let sname_ptr = path_ptr.share((path.len() + 1) as i64);
                sname_ptr.write_c_string("start").unwrap();

                let mut buffer = [0u8; INFO_SIZE];
                let info = unsafe { &mut *(buffer.as_mut_ptr() as *mut DlInfo) };
                info.dli_fname = path_ptr.addr;
                info.dli_fbase = module.virtual_base;
                info.dli_sname = sname_ptr.addr;
                info.dli_saddr = entry_point;
                emu.backend.mem_write(info_ptr, buffer.as_slice()).unwrap();

                if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                    debug!("syscall dladdr(addr=0x{:X}, info_ptr=0x{:X}, path={}) => Module(name={}, unk)", addr, info_ptr, path, module.name);
                }

                RET(1)
            }
        } else {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                debug!("syscall dladdr(addr=0x{:X}, info_ptr=0x{:X}) => NotFound", addr, info_ptr);
            }
        }
        RET(0)
    }
}

impl<T: Clone> Arm64Svc<T> for DlSym {
    fn name(&self) -> &str {
        "DlSym"
    }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let handle = emu.backend.reg_read(RegisterARM64::X0).unwrap_or(0);
        let name_ptr = emu.backend.reg_read(RegisterARM64::X1).unwrap_or(0);
        let name = emu.backend.mem_read_c_string(name_ptr).unwrap_or_default();
        warn!("dlsym not implemented: handle=0x{:X} name={}", handle, name);
        RET(0)
    }
}

impl<T: Clone> Arm64Svc<T> for DlUnwindFindExidx {
    fn name(&self) -> &str {
        "DlUnwindFindExidx"
    }

    fn handle(&self, _emu: &AndroidEmulator<T>) -> SvcCallResult {
        RET(0)
    }
}
