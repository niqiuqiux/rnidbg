# rnidbg

Rust ARM64 userland runtime for Android **API 36** (Android 16). Inspired by
[unidbg](https://github.com/zhkl0228/unidbg), scoped to:

- ELF / PIE load and process entry (`exec`)
- JNI facade (`JavaVM` / `JNIEnv`, `JNI_OnLoad`, `FindClass`, `Call*`, `RegisterNatives`)

It does **not** run Java bytecode, ARM32, iOS, ART, hypervisor/KVM, GDB, or
inline hooks. Unknown syscalls return `-ENOSYS`. Unimplemented JNI calls return
`JNI_ERR` / `0` instead of panicking.

Default CPU backend is **Dynarmic**. Unicorn 2.1.4 is optional.

## Status

| Path | What works |
|------|------------|
| `rnidbg exec --bin tests/fixtures/arm64/hello` | Freestanding `write` + `exit_group(0)` |
| `rnidbg jni --so tests/fixtures/arm64/libnative.so --onload` | `JNI_OnLoad` returns a valid JNI version |
| `rnidbg exec --bin tests/fixtures/arm64/printf` | Libc-linked PIE: bionic crt runs `main`, libc `write(1)` prints `complete pie from rnidbg`, host exit 0 |
| `rnidbg exec --bin tests/fixtures/arm64/test` | Signals, `statfs`, `dl_iterate_phdr`, pthread/cond handshake, properties. Host exits 0. On Windows a remaining-mutex deadlock after the child exits is unlocked then the host `TerminateProcess`es (resuming the JIT here used to AV). Guest stdout is often empty because `exit_group` does not flush libc stdio. |
| `rnidbg jni --so tests/fixtures/arm64/libhwdetect.so --call Java_…_runHardwareBreakpointCheck` | Loads the NDK SO, calls the JNI export, and returns the JSON report (`maxScore:280`). `R_AARCH64_ABS64` now applies RELA `r_addend` (needed for libc++ VTT / `stdout`). Guest `printf`/`puts` are hooked to `write(1)` so FILE* vfprintf does not trip stack-protector. `libandroid.so` is a virtual module by default. pthread children are queued but not preempted on Windows (resuming the JIT after `clone` AVs), so the report still scores 0 / “受限”. Host exit 0. |

`fork` is a stub (fake child pid). System `libc++.so` constructors are skipped when it is only a `DT_NEEDED` of `liblog`. Pull extra device libs with `android/sdk36/pull.ps1`; set `RNIDBG_REAL_LIBANDROID=1` to load the pulled `libandroid.so` instead of the stub.

## Requirements

- Rust 1.79+
- CMake + Ninja (Dynarmic is built from the in-tree sources)
- Windows: MSVC Build Tools; Boost headers via `BOOST_INCLUDEDIR` / `BOOST_ROOT`, or `C:\vcpkg\installed\x64-windows\include`
- Linux: C++20 toolchain; Boost headers if they are not on the default include path
- Real Android 16 **arm64** bionic (`system/lib64/libc.so`, …). NDK sysroot stubs will not boot.

## Android 36 system root

Default root is `./android/sdk36` (`system/lib64`, `system/bin`). This repo ships
the libraries pulled for development. To refresh from a connected API 36
aarch64 device or GSI:

```powershell
powershell -File android/sdk36/pull.ps1
```

Use another tree with `BASE_PATH`:

```powershell
$env:BASE_PATH = "D:\images\android16"
```

Page size is fixed at **4 KiB** (`AT_PAGESZ=0x1000`). 16 KiB generic images are
not supported. Device `ld-android.so` is a stub; rnidbg patches `__loader_*`
and a `libc_shared_globals` page at `0xfffd0000`.

See [android/sdk36/README.md](android/sdk36/README.md) for the minimum file set
and API 36 reloc notes (`DT_RELR`, `R_AARCH64_IRELATIVE`, GNU IFUNC).

## Build and run

```powershell
# Dynarmic (default)
cargo build -p rnidbg --features dynarmic

$env:BASE_PATH = "./android/sdk36"
$env:RUST_LOG  = "info"

# Freestanding hello
.\target\debug\rnidbg.exe exec --bin tests\fixtures\arm64\hello

# JNI_OnLoad
.\target\debug\rnidbg.exe jni --so tests\fixtures\arm64\libnative.so --onload

# libc-linked fixture (signals / pthread / properties)
.\target\debug\rnidbg.exe exec --bin tests\fixtures\arm64\test

# NDK JNI SO without JNI_OnLoad
.\target\debug\rnidbg.exe jni --so tests\fixtures\arm64\libhwdetect.so --call Java_com_niqiuqiux_androidhwdetect_MainActivity_runHardwareBreakpointCheck
```

```text
rnidbg exec --bin <path> [--] [args...]
rnidbg jni  --so  <path> [--onload] [--call <Java_symbol>]
```

Unicorn backend:

```powershell
cargo build -p rnidbg --no-default-features --features unicorn
```

## Library API

```rust
use emulator::AndroidEmulator;

let emu = AndroidEmulator::create_arm64(2667, 2427, "app", ());
emu.set_exec_path("libfoo.so");

// Shared object + JNI
let vm = emu.create_jni_env();
let module = vm.load_library(emu.clone(), "libfoo.so", true)?;
vm.call_jni_onload(emu.clone(), unsafe { &*module.get() })?;

// PIE / ET_EXEC process entry (kernel argument block + auxv)
let module = emu.load_library("tests/fixtures/arm64/hello", true)?;
unsafe { &*module.get() }.call_entry(&emu, &["hello"])?;

emu.destroy();
```

Two session shapes:

- **Library / JNI** — load `.so`, resolve `JNI_OnLoad`, dispatch through the
  SvcMemory JNI table (`DalvikVM64` is a facade only).
- **Process** — load ELF, build argv/envp/auxv, `e_entry` until `exit` /
  `exit_group`.

## Guest ABI

| Item | Value |
|------|--------|
| ISA | AArch64 only |
| Page size | `0x1000` |
| JNI handle tags | class `0x7001`, ref `0x7002`, object `0x7003` (high 16 bits) |
| `AT_HWCAP` | FP \| ASIMD \| AES \| PMULL \| SHA1 \| SHA2 \| CRC32. **No** `HWCAP_ATOMICS` (bit 8), **no** `HWCAP_CPUID` (bit 11) — Dynarmic cannot run LSE `CAS`/`LDADD` or `mrs MIDR_EL1`. |
| PAC / BTI | HINT encodings on RX pages are rewritten to `NOP` at load |
| `ro.build.version.sdk` | 36 |
| Unknown syscall | `-ENOSYS` |
| Unimplemented JNI | `JNI_ERR` or `0` (`SoftJniZero`) |

API 36 pthread clone uses `tls = TCB+24` (`CLONE_SETTLS`). `TPIDR_EL0` must be
that value so `TPIDR+8` is the `pthread*`, not the old Marshmallow `pthread+0xb0`.

## What is implemented

- ELF loader: `PT_LOAD`, `DT_RELR`, `R_AARCH64_IRELATIVE`, `R_AARCH64_TLS_TPREL`, static `ET_EXEC` without `PT_DYNAMIC`, GNU IFUNC
- Kernel argument block: argv, envp, auxv (`AT_PHDR`, `AT_HWCAP`, `AT_RANDOM`, …)
- Virtual `__loader_*` / `dl_iterate_phdr` / `dlopen` family (fail-soft)
- Syscalls used by SDK 36 bionic: `write`, `exit_group`, `mmap`/`mprotect`/`munmap`, `prctl`, `rt_sig*`, `clone` (bionic pthread), `futex` (`WAIT`/`WAKE` and `*_BITSET`), `clock_gettime`, `nanosleep`, `getrandom`, `faccessat`/`faccessat2`, `statfs`, `pipe2`, `sched_*`, `ppoll` (returns 0), …
- Cooperative guest threads; deadlock recovery unlocks a contended mutex left by an exited thread
- JNI: `JNI_OnLoad`, `FindClass`, `RegisterNatives`, `NewObject` / `Call*Object` / `Call*Int` / `Call*Void` (instance and static). Remaining primitives and field accessors are fail-soft zeros
- System properties: `__system_property_get` / `find` / `read` with bionic `prop_info` layout (`serial` high byte = value length)

## Fixtures

| File | Notes |
|------|--------|
| `tests/fixtures/arm64/hello.c` | Freestanding `svc` `write` + `exit_group`. Build with NDK `aarch64-linux-android35-clang -nostdlib -static -Wl,-e,_start` |
| `tests/fixtures/arm64/hello` | Prebuilt hello |
| `tests/fixtures/arm64/printf.c` | Libc-linked PIE: `write(1, "complete pie from rnidbg\\n")` |
| `tests/fixtures/arm64/printf` | Prebuilt PIE (NDK clang `-fPIE -pie`; runtime libc from `android/sdk36`) |
| `tests/fixtures/arm64/libnative.so` | Minimal JNI `JNI_OnLoad` |
| `tests/fixtures/arm64/test` | Device-style libc binary (signals, pthread, netlink, properties) |

## Environment

Runtime:

| Variable | Meaning | Default |
|----------|---------|---------|
| `BASE_PATH` | Android system root (`system/lib64`, `system/bin`) | `./android/sdk36` |
| `RUST_LOG` | `env_logger` filter | `info` (CLI sets this if unset) |
| `DYNARMIC_JIT_SIZE` | Dynarmic code cache, MiB (clamped 8–128) | `64` |
| `DYNARMIC_TRACE` | Print each `dynarmic_emu_start` pc | unset |

Compile-time (`option_env!`, rebuild required). Set to `1` to enable:

| Variable | Meaning |
|----------|---------|
| `PRINT_SYSCALL_LOG` | Guest syscall arguments |
| `PRINT_SYSCALL_TIME_COST` | Syscall timing |
| `SHOW_INIT_FUNC_CALL` | `.init_array` / `DT_INIT` calls |
| `SHOW_INIT_FUNC_PUSH` | Init-function queue |
| `SHOW_MODULES_INSERT_LOG` | Module insert |
| `SHOW_LIBC_TRY_LINK` | libc symbol hooks |
| `PRINT_SVC_REGISTER` | SvcMemory registrations |
| `PRINT_JNI_CALLS` | JNI table calls |
| `PRINT_JNI_CALLS_EX` | Extra JNI dumps |
| `PRINT_SYSTEM_PROP_LOG` | `__system_property_*` |
| `PRINT_STRING_LOG` | Hooked `strcmp` / `strncmp` |
| `PRINT_MMAP_LOG` | Guest mmap |
| `EMU_LOG` | Emulate begin/until |
| `DYNARMIC_DEBUG` | Dynarmic Rust binding traces |

## Layout

```
rnidbg          CLI (exec / jni)
emulator        Loader, syscalls, threads, JNI facade
dynarmic        Vendored Dynarmic + C wrapper (A64)
unicorn         Optional Unicorn 2.1.4
android/sdk36   API 36 arm64 bionic image + pull.ps1
tests/fixtures  hello / libnative.so / test
```

## Known gaps

- Host heap corruption after a long `exec` (often after `exit_group`)
- `fork` does not create a second address space
- No Java interpreter / ART; JNI is a native facade
- Many `Call*Byte/Char/Short/Long/Float/Double` and field accessors are stubs
- No GDB stub, inline hook, or hypervisor
- PAC keys / BTI are not emulated (HINT → NOP)

## License

See [LICENSE](LICENSE). Dynarmic, Unicorn, and Android binaries keep their own
licenses.

## Thanks

- [unidbg](https://github.com/zhkl0228/unidbg)
- [dynarmic](https://github.com/azahar-emu/dynarmic) (azahar-emu 6.7 line)
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)
- [Rust](https://www.rust-lang.org/)
