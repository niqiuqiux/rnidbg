pub mod android;
pub mod emulator;
pub mod keystone;
pub mod linux;
pub mod memory;
pub mod pointer;
pub(crate) mod tool;
pub(crate) mod elf;
mod backend;

pub use emulator::AndroidEmulator;
pub use linux::LinuxModule;

/// End the host process without running CRT/JIT destructors.
/// Returning from a long Dynarmic run into `std::process::exit` (atexit /
/// DLL detach) has been seen to AV or trip `STATUS_HEAP_CORRUPTION`.
pub fn terminate_host(status: i32) -> ! {
    #[cfg(windows)]
    unsafe {
        type Handle = *mut std::ffi::c_void;
        extern "system" {
            fn GetCurrentProcess() -> Handle;
            fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
        }
        let _ = TerminateProcess(GetCurrentProcess(), status as u32);
    }
    std::process::abort()
}