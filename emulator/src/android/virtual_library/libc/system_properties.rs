// https://android.googlesource.com/platform/bionic/+/0d787c1fa18c6a1f29ef9840e28a68cf077be1de/libc/bionic/system_properties.c

use std::mem::size_of;
use std::rc::Rc;
use anyhow::anyhow;
use log::{debug, error};
use crate::backend::RegisterARM64;
use crate::emulator::AndroidEmulator;
use crate::linux::structs::PropInfo;
use crate::memory::svc_memory::{Arm64Svc, SvcCallResult};
use crate::memory::svc_memory::SvcCallResult::{FUCK, RET};

pub(super) struct SystemPropertyGet(Option<Rc<Box<dyn Fn(&str) -> Option<String>>>>);
pub(super) struct SystemPropertyFind(Option<Rc<Box<dyn Fn(&str) -> Option<String>>>>);
pub(super) struct SystemPropertyRead(Option<Rc<Box<dyn Fn(&str) -> Option<String>>>>);

impl SystemPropertyGet {
    pub fn new(
        service: Option<Rc<Box<dyn Fn(&str) -> Option<String>>>>
    ) -> Self {
        SystemPropertyGet(service)
    }
}

impl SystemPropertyFind {
    pub fn new(
        service: Option<Rc<Box<dyn Fn(&str) -> Option<String>>>>
    ) -> Self {
        SystemPropertyFind(service)
    }
}

impl SystemPropertyRead {
    pub fn new(
        service: Option<Rc<Box<dyn Fn(&str) -> Option<String>>>>
    ) -> Self {
        SystemPropertyRead(service)
    }
}

impl<T: Clone> Arm64Svc<T> for SystemPropertyGet {
    fn name(&self) -> &str { "SystemPropertyGet" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let backend = &emu.backend;
        let Ok(name_pointer) = backend.reg_read(RegisterARM64::X0) else {
            return FUCK(anyhow!("unable to get name_pointer"))
        };
        let Ok(name) = backend.mem_read_c_string(name_pointer) else {
            return FUCK(anyhow!("unable to read name from name pointer: 0x{:X}", name_pointer))
        };
        let Ok(value) = backend.reg_read(RegisterARM64::X1) else {
            return FUCK(anyhow!("unable to get value when handle SystemPropGet"))
        };

        if option_env!("PRINT_SYSTEM_PROP_LOG") == Some("1") {
            debug!("__system_property_get({}, 0x{:X})", name, value);
        }

        let builtin = default_system_property(&name);
        let env = self.0.as_ref().and_then(|s| s(&name)).or(builtin).unwrap_or_default();
        if let Err(e) = write_prop_value(backend, value, &env) {
            return FUCK(e);
        }
        RET(env.len().min(91) as i64)
    }
}

impl<T: Clone> Arm64Svc<T> for SystemPropertyFind {
    fn name(&self) -> &str { "SystemPropertyFind" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let backend = &emu.backend;
        let Ok(name_pointer) = backend.reg_read(RegisterARM64::X0) else {
            return FUCK(anyhow!("unable to get name_pointer"))
        };
        let Ok(name) = backend.mem_read_c_string(name_pointer) else {
            return FUCK(anyhow!("unable to read name from name pointer: 0x{:X}", name_pointer))
        };

        if option_env!("PRINT_SYSTEM_PROP_LOG") == Some("1") {
            debug!("__system_property_find({})", name);
        }
        
        if name == "debug.atrace.tags.enableflags" {
            return RET(0)
        }

        let lookup = self.0.as_ref().and_then(|s| s(&name)).or_else(|| default_system_property(&name));
        match lookup {
            Some(env) => {
                let buf = pack_prop_info(&name, &env);
                let Ok(pointer) = emu.falloc(buf.len(), true) else {
                  return FUCK(anyhow!("unable to alloc memory for prop_info"))
                };
                if let Err(e) = pointer.write_data(&buf) {
                    return FUCK(anyhow!("unable to write prop_info: {}", e))
                }
                RET(pointer.addr as i64)
            }
            None =>  RET(0)
        }
    }
}

fn default_system_property(name: &str) -> Option<String> {
    match name {
        "ro.build.version.sdk" => Some(crate::android::sdk::ANDROID_SDK.to_string()),
        "ro.build.version.release" => Some("16".to_string()),
        "ro.build.version.security_patch" => Some("2025-12-01".to_string()),
        "ro.product.cpu.abi" | "ro.product.cpu.abilist" => Some("arm64-v8a".to_string()),
        "ro.product.first_api_level" | "ro.board.first_api_level" | "ro.vendor.api_level" => {
            Some(crate::android::sdk::ANDROID_SDK.to_string())
        }
        "ro.debuggable" => Some("0".to_string()),
        "ro.secure" => Some("1".to_string()),
        "ro.kernel.qemu" | "libc.debug.malloc" => Some(String::new()),
        "ro.zygote" => Some("zygote64".to_string()),
        "ro.boot.verifiedbootstate" => Some("green".to_string()),
        "ro.boot.vbmeta.device_state" => Some("locked".to_string()),
        "ro.boot.flash.locked" => Some("1".to_string()),
        "sys.usb.state" => Some("adb".to_string()),
        _ => None,
    }
}

fn pack_prop_info(name: &str, value: &str) -> Vec<u8> {
    let vlen = value.len().min(91);
    let nlen = name.len().min(95);
    let mut buf = vec![0u8; size_of::<PropInfo>()];
    let serial = (vlen as u32) << 24;
    buf[0..4].copy_from_slice(&serial.to_le_bytes());
    buf[4..4 + vlen].copy_from_slice(&value.as_bytes()[..vlen]);
    buf[96..96 + nlen].copy_from_slice(&name.as_bytes()[..nlen]);
    buf
}

fn write_prop_value<T: Clone>(backend: &crate::backend::Backend<T>, addr: u64, value: &str) -> anyhow::Result<()> {
    let bytes = value.as_bytes();
    let n = bytes.len().min(91);
    backend.mem_write(addr, &bytes[..n])?;
    backend.mem_write(addr + n as u64, b"\0")?;
    Ok(())
}

impl<T: Clone> Arm64Svc<T> for SystemPropertyRead {
    fn name(&self) -> &str { "SystemPropertyRead" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let backend = &emu.backend;
        let Ok(pi) = backend.reg_read(RegisterARM64::X0) else {
            return RET(0);
        };
        let Ok(name_out) = backend.reg_read(RegisterARM64::X1) else {
            return RET(0);
        };
        let Ok(value_out) = backend.reg_read(RegisterARM64::X2) else {
            return RET(0);
        };
        if pi == 0 || value_out == 0 {
            return RET(0);
        }
        let mut serial_bytes = [0u8; 4];
        if backend.mem_read(pi, &mut serial_bytes).is_err() {
            return RET(0);
        }
        let serial = u32::from_le_bytes(serial_bytes);
        let vlen = (serial >> 24) as usize;
        let mut value = vec![0u8; vlen.min(91) + 1];
        if backend.mem_read(pi + 4, &mut value).is_err() {
            return RET(0);
        }
        let _ = backend.mem_write(value_out, &value);
        if name_out != 0 {
            let mut name = [0u8; 32];
            if backend.mem_read(pi + 96, &mut name).is_ok() {
                let _ = backend.mem_write(name_out, &name);
            }
        }
        RET(vlen.min(91) as i64)
    }
}