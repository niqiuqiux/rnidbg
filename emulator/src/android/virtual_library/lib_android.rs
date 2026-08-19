use std::collections::HashMap;
use std::path::Path;
use log::warn;
use crate::emulator::{AndroidEmulator, RcUnsafeCell};
use crate::linux::LinuxModule;
use crate::memory::svc_memory::{SimpleArm64Svc, SvcCallResult};

const SO_NAME: &str = "libandroid.so";

fn android_stub<T: Clone>(name: &str, emulator: &AndroidEmulator<T>) -> SvcCallResult {
    warn!("libandroid.so {name} stub => 0");
    let _ = emulator;
    SvcCallResult::RET(0)
}

/// NDK `libandroid.so` (AAssetManager_*) is not on the pulled SDK 36 image.
/// Hardware-detect and many JNI SOs still `DT_NEEDED` it. Mirror unidbg
/// `AndroidModule`: a virtual module so the loader can resolve the soname.
/// Stubs fail-soft (return 0) — this SO does not import the AAsset symbols.
pub fn register<'a, T: Clone>(emu: &AndroidEmulator<'a, T>) -> RcUnsafeCell<LinuxModule<'a, T>> {
    let names = [
        "AAssetManager_fromJava",
        "AAssetManager_open",
        "AAsset_close",
        "AAsset_getBuffer",
        "AAsset_getLength",
        "AAsset_read",
    ];
    let mut symbols = HashMap::new();
    {
        let svc = &mut emu.inner_mut().svc_memory;
        for name in names {
            symbols.insert(
                name.to_string(),
                svc.register_svc(SimpleArm64Svc::new(name, android_stub)),
            );
        }
    }
    emu.inner_mut()
        .memory
        .load_virtual_module(SO_NAME.to_string(), symbols)
}

/// Prefer the virtual module. Device `libandroid.so` pulls binder/hwui/EGL
/// plus vendor-only sonames that cannot boot as a DT_NEEDED of a JNI SO.
/// Set `RNIDBG_REAL_LIBANDROID=1` to load the pulled file instead.
pub fn ensure_registered<T: Clone>(emu: &AndroidEmulator<T>) {
    if emu.inner_mut().memory.modules.contains_key(SO_NAME) {
        return;
    }
    if std::env::var("RNIDBG_REAL_LIBANDROID").ok().as_deref() == Some("1") {
        let base = emu.inner_mut().base_path.clone();
        let path = Path::new(&crate::android::sdk::lib64_dir(&base)).join(SO_NAME);
        if path.exists() {
            return;
        }
    }
    let _ = register(emu);
}
