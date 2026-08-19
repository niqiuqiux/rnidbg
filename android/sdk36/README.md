# Android 36 (arm64) system root

rnidbg targets **API 36** (Android 16) bionic, not unidbg's bundled SDK 23.

This directory must contain at least:

```
system/lib64/libc.so
system/lib64/libdl.so
system/lib64/libm.so
system/lib64/liblog.so
system/lib64/libandroid.so   # optional; JNI SOs use a virtual stub unless RNIDBG_REAL_LIBANDROID=1
```

NDK sysroot `libc.so` files are **stubs** (~240KB) and will not boot. Pull real
device / GSI libraries:

```powershell
# API 36 aarch64 device or GSI attached via adb
powershell -File android/sdk36/pull.ps1
```

Override the root with `BASE_PATH` if you keep the image elsewhere.

Compatibility notes vs SDK 23:

- `DT_RELR` / `DT_ANDROID_RELR` packed relative relocs
- `R_AARCH64_IRELATIVE` ifuncs
- extra syscalls used by modern bionic: `rseq`, `set_robust_list`, `membarrier`, `getrandom`, `faccessat2`
- default `ro.build.version.sdk=36`
- page size stays 4KB (`AT_PAGESZ=0x1000`); 16KB generic images are not supported yet
