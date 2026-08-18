# RNIDBG

ARM64 Android **API 36** userland runtime in Rust (unidbg-inspired).
JNI facade + ELF/PIE process entry. No Java bytecode, no ARM32, no iOS.

## Build

- Rust 1.79+
- Linux: `libfmt` / `boost` for the dynarmic backend

## Android 36 system root

Real bionic libraries are required (NDK stubs will not boot):

```powershell
powershell -File android/sdk36/pull.ps1
```

Default root is `./android/sdk36`. Override with `BASE_PATH`.

## CLI

```text
rnidbg exec --bin tests/fixtures/arm64/test
rnidbg jni  --so  tests/fixtures/arm64/libnative.so --onload
```

Library API:

```rust
let emu = AndroidEmulator::create_arm64(2667, 2427, "app", ());
let module = emu.load_library("libfoo.so", true)?;
let vm = emu.create_jni_env();
vm.call_jni_onload(emu.clone(), unsafe { &*module.get() })?;
// or: unsafe { &*module.get() }.call_entry(&emu, &["--help"])?;
```

## DEVELOPER DEBUGGING COMPILE TIME VARIABLES

| 变量名                     | 说明                             | 默认值 |
|-------------------------|--------------------------------|-----|
| PRINT_SYSCALL_LOG       | print syscall log              | 0   |
| SHOW_INIT_FUNC_CALL     | print `init_function` calls    | 0   |
| SHOW_MODULES_INSERT_LOG | print module loading log       | 0   |
| PRINT_SVC_REGISTER      | print service registration log | 0   |
| PRINT_JNI_CALLS         | print jni call log             | 0   |
| DYNARMIC_DEBUG          | print dynarmic logs            | 0   |
| EMU_LOG                 | print emulator logs            | 0   |
| PRINT_MMAP_LOG          | print virtual mmap logs        | 0   |

## RUN TIME VARIABLE IN COMPUTING

| VARIABLE NAME     | CLARIFICATION        | DEFAULT VALUE |
|-------------------|----------------------|---------------|
| DYNARMIC_JIT_SIZE | Code Cache Size (MB) | 64            |

## TODO

- [ ] Add support for debugging
- [ ] Add support for more syscall
- [ ] Beautiful JNI implementation (unsafe block)
- [ ] Implement most system libraries as virtual modules

## Thanks

- [Rust](https://www.rust-lang.org/)
- [unidbg](https://github.com/zhkl0228/unidbg)
- [dynarmic](https://github.com/lioncash/dynarmic)
- [Dobby](https://github.com/jmpews/Dobby)
