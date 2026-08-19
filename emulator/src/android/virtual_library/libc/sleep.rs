use log::info;

use crate::backend::RegisterARM64;
use crate::emulator::AndroidEmulator;
use crate::memory::svc_memory::{Arm64Svc, SvcCallResult};
use crate::memory::svc_memory::SvcCallResult::RET;

/// Zero a guest `timespec` (16 bytes) when the caller passed a remainder pointer.
fn zero_timespec<T: Clone>(emu: &AndroidEmulator<T>, addr: u64) {
    if addr != 0 {
        let _ = emu.backend.mem_write(addr, &[0u8; 16]);
    }
}

/// `usleep` / `nanosleep` / `clock_nanosleep` must not enter the libc SVC
/// wrapper: after a cooperative Halt, Dynarmic resume into the post-SVC `cmn`
/// has been seen to AV the Windows host. The hook stub is `svc; ret`, so
/// `continue_run` skip-to-LR returns to the caller (hwdetect), not libc.
///
/// When other threads exist, Halt so the dispatcher can run them.
fn sleep_and_yield<T: Clone>(emu: &AndroidEmulator<T>, rem: u64, label: &str) -> SvcCallResult {
    zero_timespec(emu, rem);
    let yielded = emu.yield_to_other_threads();
    if yielded {
        info!("libc {label}: yield");
    }
    RET(0)
}

pub(super) struct Usleep;
pub(super) struct Nanosleep;
pub(super) struct ClockNanosleep;
pub(super) struct Sigaction;

impl<T: Clone> Arm64Svc<T> for Usleep {
    fn name(&self) -> &str { "usleep" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        sleep_and_yield(emu, 0, "usleep")
    }
}

impl<T: Clone> Arm64Svc<T> for Nanosleep {
    fn name(&self) -> &str { "nanosleep" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let rem = emu.backend.reg_read(RegisterARM64::X1).unwrap_or(0);
        sleep_and_yield(emu, rem, "nanosleep")
    }
}

impl<T: Clone> Arm64Svc<T> for ClockNanosleep {
    fn name(&self) -> &str { "clock_nanosleep" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let rem = emu.backend.reg_read(RegisterARM64::X3).unwrap_or(0);
        sleep_and_yield(emu, rem, "clock_nanosleep")
    }
}

impl<T: Clone> Arm64Svc<T> for Sigaction {
    fn name(&self) -> &str { "sigaction" }

    fn handle(&self, emu: &AndroidEmulator<T>) -> SvcCallResult {
        let signum = emu.backend.reg_read(RegisterARM64::X0).unwrap_or(0);
        let oldact = emu.backend.reg_read(RegisterARM64::X2).unwrap_or(0);
        info!("libc sigaction(sig={}) stub", signum);
        if oldact != 0 {
            let _ = emu.backend.mem_write(oldact, &[0u8; 32]);
        }
        RET(0)
    }
}
