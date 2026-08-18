/// Guest Android API level used for the bundled system image and
/// `ro.build.version.sdk`. Unidbg ships 19/23; this runtime targets 36.
pub const ANDROID_SDK: u32 = 36;

/// Guest `AT_HWCAP` / ifunc `_hwcap`. Dynarmic cannot execute LSE atomics
/// (`CAS`/`LDADD`) or `mrs MIDR_EL1`, so `HWCAP_ATOMICS` (bit 8) and
/// `HWCAP_CPUID` (bit 11) stay clear. FP | ASIMD | AES | PMULL | SHA1 | SHA2 | CRC32.
pub const GUEST_HWCAP: u64 =
    (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);

/// Default host directory for the Android 36 system root
/// (`system/lib64`, `system/bin`, ...).
pub const DEFAULT_SDK_ROOT: &str = "./android/sdk36";

pub fn default_sdk_root() -> String {
    std::env::var("BASE_PATH").unwrap_or_else(|_| DEFAULT_SDK_ROOT.to_string())
}

pub fn lib64_dir(base_path: &str) -> String {
    let root = if base_path.is_empty() {
        DEFAULT_SDK_ROOT
    } else {
        base_path
    };
    format!("{}/system/lib64", root)
}

pub fn bin_dir(base_path: &str) -> String {
    let root = if base_path.is_empty() {
        DEFAULT_SDK_ROOT
    } else {
        base_path
    };
    format!("{}/system/bin", root)
}
