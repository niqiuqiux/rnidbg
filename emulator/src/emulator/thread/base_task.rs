use log::warn;

use crate::emulator::AndroidEmulator;
use crate::emulator::func::FunctionCall;
use crate::emulator::memory::{MemoryBlockTrait, MemoryBlock};
use crate::emulator::thread::{DestroyListener, RunnableTask, Waiter, waiter, WaiterTrait, TaskStatus};
use crate::pointer::VMPointer;
use hashbag::HashBag;
use crate::backend::RegisterARM64;
use crate::linux::thread::{FutexIndefinitelyWaiter, FutexNanoSleepWaiter};
use crate::backend::Context;

const THREAD_STACK_SIZE: i32 = 0x80000;

/// Guest GPRs owned in Rust. Dynarmic's malloc'd context blob has been
/// seen to come back null after a worker slice on Windows.
#[derive(Clone, Debug)]
pub struct Arm64Snap {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u64,
    pub tpidr: u64,
}

fn gpr(i: usize) -> RegisterARM64 {
    match i {
        0 => RegisterARM64::X0,
        1 => RegisterARM64::X1,
        2 => RegisterARM64::X2,
        3 => RegisterARM64::X3,
        4 => RegisterARM64::X4,
        5 => RegisterARM64::X5,
        6 => RegisterARM64::X6,
        7 => RegisterARM64::X7,
        8 => RegisterARM64::X8,
        9 => RegisterARM64::X9,
        10 => RegisterARM64::X10,
        11 => RegisterARM64::X11,
        12 => RegisterARM64::X12,
        13 => RegisterARM64::X13,
        14 => RegisterARM64::X14,
        15 => RegisterARM64::X15,
        16 => RegisterARM64::X16,
        17 => RegisterARM64::X17,
        18 => RegisterARM64::X18,
        19 => RegisterARM64::X19,
        20 => RegisterARM64::X20,
        21 => RegisterARM64::X21,
        22 => RegisterARM64::X22,
        23 => RegisterARM64::X23,
        24 => RegisterARM64::X24,
        25 => RegisterARM64::X25,
        26 => RegisterARM64::X26,
        27 => RegisterARM64::X27,
        28 => RegisterARM64::X28,
        29 => RegisterARM64::X29,
        30 => RegisterARM64::LR,
        _ => RegisterARM64::XZR,
    }
}

pub(crate) fn capture_snap<T: Clone>(emulator: &AndroidEmulator<T>) -> Arm64Snap {
    let b = &emulator.backend;
    let mut x = [0u64; 31];
    for i in 0..31 {
        x[i] = b.reg_read(gpr(i)).unwrap_or(0);
    }
    Arm64Snap {
        x,
        sp: b.reg_read(RegisterARM64::SP).unwrap_or(0),
        pc: b.reg_read(RegisterARM64::PC).unwrap_or(0),
        nzcv: b.reg_read(RegisterARM64::NZCV).unwrap_or(0),
        tpidr: b.reg_read(RegisterARM64::TPIDR_EL0).unwrap_or(0),
    }
}

fn apply_snap<T: Clone>(emulator: &AndroidEmulator<T>, snap: &Arm64Snap) {
    let b = &emulator.backend;
    for i in 0..31 {
        let _ = b.reg_write(gpr(i), snap.x[i]);
    }
    let _ = b.reg_write(RegisterARM64::SP, snap.sp);
    let _ = b.reg_write(RegisterARM64::PC, snap.pc);
    let _ = b.reg_write(RegisterARM64::NZCV, snap.nzcv);
    let _ = b.reg_write(RegisterARM64::TPIDR_EL0, snap.tpidr);
}

pub struct BaseTask<'a, T: Clone> {
    pub waiter: Option<Waiter<'a, T>>,
    pub context: Option<Context>,
    pub snap: Option<Arm64Snap>,
    pub stack_block: Option<MemoryBlock<'a, T>>,
    pub destroy_listener: Option<Box<dyn DestroyListener<'a, T>>>,
    pub stack: Vec<FunctionCall>,
    pub bag: HashBag<u64>,
    pub status: TaskStatus,
    /// When true, `continue_run` jumps to LR if `pc-4` is an SVC. Set after a
    /// Halt from a kernel/hook SVC so we skip libc's post-SVC `cmn`. Planted
    /// fork-child snaps leave this false so they execute the fork wrapper ret.
    pub skip_svc_epilogue: bool,
}

impl <'a, T: Clone> BaseTask<'a, T> {
    pub fn new() -> Self {
        Self {
            waiter: None,
            context: None,
            snap: None,
            stack_block: None,
            destroy_listener: None,
            stack: Vec::new(),
            bag: HashBag::new(),
            status: TaskStatus::Z,
            skip_svc_epilogue: false,
        }
    }

    pub fn set_waiter(&mut self, waiter: Waiter<'a, T>) {
        self.waiter = Some(waiter);
    }

    pub fn get_waiter(&mut self) -> Option<&mut Waiter<'a, T>> {
        if let Some(waiter) = &mut self.waiter {
            return Some(waiter)
        }
        None
    }

    pub fn continue_run(&mut self, emulator: &AndroidEmulator<'a, T>, until: u64) -> Option<u64> {
        let backend = emulator.backend.clone();
        if let Some(context) = &self.context {
            if let Err(e) = backend.context_restore(context) {
                warn!("dynarmic context restore failed: {e}; using Arm64Snap");
            }
        }
        if let Some(snap) = &self.snap {
            apply_snap(emulator, snap);
        }
        let mut pc = backend.reg_read(RegisterARM64::PC)
            .expect("[continue_run] failed to get pc");
        let lr = backend.reg_read(RegisterARM64::LR).unwrap_or(0);
        let x0 = backend.reg_read(RegisterARM64::X0).unwrap_or(0);
        let x8 = backend.reg_read(RegisterARM64::X8).unwrap_or(0);
        // After Halt in a leaf `svc #0`, resume at LR. Returning into the
        // post-SVC CMN/RET of the libc wrapper has been seen to AV the host.
        // Fresh fork-child snaps must not skip: they still need the wrapper `ret`.
        if self.skip_svc_epilogue && lr != 0 && pc >= 4 {
            let mut insn = [0u8; 4];
            if backend.mem_read(pc - 4, &mut insn).is_ok() {
                let w = u32::from_le_bytes(insn);
                if w & 0xffe0_001f == 0xd400_0001 {
                    let _ = backend.reg_write(RegisterARM64::PC, lr);
                    pc = lr;
                }
            }
        }
        self.skip_svc_epilogue = false;
        log::debug!(
            "continue_run pc=0x{:x} lr=0x{:x} x0=0x{:x} x8=0x{:x} until=0x{:x}",
            pc, lr, x0, x8, until
        );
        // Drop block-link / RSB state from the previous cooperative slice.
        // emu_start now leaves CacheInvalidation set so this actually runs.
        backend.clear_jit_cache();
        if let Some(waiter) = &self.waiter {
            match waiter {
                Waiter::FutexIndefinite(futex_waiter) => {
                    futex_waiter.on_continue_run(emulator);
                }
                Waiter::FutexNanoSleep(futex_task) => {
                    futex_task.on_continue_run(emulator);
                }
                Waiter::PipeRead(w) => {
                    w.on_continue_run(emulator);
                }
                Waiter::Poll(w) => {
                    w.on_continue_run(emulator);
                }
                Waiter::ChildExit(w) => {
                    w.on_continue_run(emulator);
                }
                Waiter::Unknown(_) => {
                    warn!("unknown waiter on continue_run, ignoring");
                }
            }
            self.waiter = None;
        }
        let ret = emulator.emulate(pc, until);
        log::debug!("continue_run finished pc=0x{:x} ret={:?}", pc, ret);
        ret
    }

    pub fn allocate_stack(&mut self, emulator: &AndroidEmulator<'a, T>) -> VMPointer<'a, T> {
        if self.stack_block.is_none() {
            let stack_block = emulator.malloc(THREAD_STACK_SIZE as usize, false)
                .expect("failed to allocate stack");
            self.stack_block = Some(stack_block);
        }
        let stack_block = self.stack_block.as_ref().unwrap();
        let stack = stack_block.pointer();
        stack.share_with_size(THREAD_STACK_SIZE as i64, 0)
    }
}

impl<'a, T: Clone> RunnableTask<'a, T> for BaseTask<'a, T> {
    fn can_dispatch(&self) -> bool {
        if let Some(waiter) = &self.waiter {
            return match waiter {
                Waiter::FutexIndefinite(futex_waiter) => {
                    <FutexIndefinitelyWaiter<'_, T> as WaiterTrait<'_, T>>::can_dispatch(futex_waiter)
                }
                Waiter::FutexNanoSleep(futex_task) => {
                    <FutexNanoSleepWaiter<'_, T> as WaiterTrait<'_, T>>::can_dispatch(futex_task)
                }
                Waiter::PipeRead(w) => w.can_dispatch(),
                Waiter::Poll(w) => w.can_dispatch(),
                Waiter::ChildExit(w) => !w.alive(),
                Waiter::Unknown(_) => {
                    warn!("unknown waiter on can_dispatch, treating as runnable");
                    true
                }
            }
        }
        true
    }

    fn save_context(&mut self, emulator: &AndroidEmulator<'a, T>) {
        self.snap = Some(capture_snap(emulator));
        self.skip_svc_epilogue = true;
        let backend = emulator.backend.clone();
        let mut context = if let Some(context) = &self.context {
            context.clone()
        } else {
            match backend.context_alloc() {
                Ok(context) => context,
                Err(e) => {
                    warn!("context_alloc failed: {e}; snap only");
                    return;
                }
            }
        };
        if let Err(e) = backend.context_save(&mut context) {
            warn!("context_save failed: {e}; snap only");
            return;
        }
        self.context = Some(context);
    }

    fn is_context_saved(&self) -> bool {
        self.snap.is_some() || self.context.is_some()
    }

    fn restore_context(&self, emulator: &AndroidEmulator<'a, T>) {
        if let Some(context) = &self.context {
            if let Err(e) = emulator.backend.context_restore(context) {
                warn!("restore_context: {e}");
            }
        }
        if let Some(snap) = &self.snap {
            apply_snap(emulator, snap);
        } else if self.context.is_none() {
            warn!("restore context failed, no snap or context")
        }
    }

    fn destroy(&self, emulator: &AndroidEmulator<'a, T>) {
        let mut smash = false;
        if let Some(memory_block) = &self.stack_block {
            let addr = memory_block.pointer.addr;
            let size = memory_block.pointer.size as u64;
            // Guest TLS / heap smash has been seen to leave a garbage
            // MemoryBlock (non-page address). Skip host munmap in that case.
            if addr == 0 || addr & 0xfff != 0 || size == 0 || size > 0x100_0000 {
                warn!(
                    "skip stack_block free: addr=0x{:x} size=0x{:x}",
                    addr, size
                );
                smash = true;
            } else {
                memory_block.free(Some(emulator.clone()))
            }
        }

        if smash {
            return;
        }

        if let Some(context) = &self.context {
            context.release();
        }

        if let Some(listener) = &self.destroy_listener {
            listener.on_destroy(emulator);
        }
    }

    fn set_waiter(&mut self, emulator: &AndroidEmulator<'a, T>, waiter: Waiter<'a, T>) {
        self.set_waiter(waiter)
    }

    fn get_waiter(&mut self) -> Option<&mut Waiter<'a, T>> {
        self.waiter.as_mut()
    }

    fn set_result(&self, emulator: &AndroidEmulator<'a, T>, ret: u64) {}

    fn set_destroy_listener(&mut self, listener: Box<dyn DestroyListener<'a, T>>) {
        self.destroy_listener = Some(listener);
    }

    fn pop_context(&mut self, emulator: &AndroidEmulator<'a, T>) {
        let backend = emulator.backend.clone();
        let off = emulator.pop_context()
            .expect("[pop_context] failed to pop context");
        let pc = backend.reg_read(RegisterARM64::PC)
            .expect("[pop_context] failed to get pc");
        backend.reg_write(RegisterARM64::PC, pc + off as u64)
            .expect("[pop_context] failed to set pc");
        self.save_context(emulator);
    }

    fn push_function(&mut self, emulator: &AndroidEmulator<'a, T>, call: FunctionCall) {
        self.bag.insert_many(call.return_address as u64, 1);
        self.stack.push(call);
    }

    fn pop_function(&mut self, emulator: &AndroidEmulator<'a, T>, address: u64) -> Option<FunctionCall> {
        if self.bag.contains(&address) > 0 {
            return None;
        }

        let call = self.stack.last(); // 栈顶元素是最后一个函数调用
        if let Some(call) = call {
            let lr = emulator.get_lr().map_err(|e| warn!("get lr failed: {:?}", e))
                .ok()?;
            if lr != call.return_address as u64 {
                return None;
            }

            let call = call.clone();
            self.bag.remove_up_to(&address, 1);
            self.stack.pop();

            Some(call)
        } else {
            panic!("pop_function failed, stack is empty")
        }
    }

    fn get_task_status(&self) -> TaskStatus {
        self.status
    }

    fn set_task_status(&mut self, status: TaskStatus) {
        self.status = status;
    }
}