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

pub struct BaseTask<'a, T: Clone> {
    pub waiter: Option<Waiter<'a, T>>,
    pub context: Option<Context>,
    pub stack_block: Option<MemoryBlock<'a, T>>,
    pub destroy_listener: Option<Box<dyn DestroyListener<'a, T>>>,
    pub stack: Vec<FunctionCall>,
    pub bag: HashBag<u64>,
    pub status: TaskStatus,
}

impl <'a, T: Clone> BaseTask<'a, T> {
    pub fn new() -> Self {
        Self {
            waiter: None,
            context: None,
            stack_block: None,
            destroy_listener: None,
            stack: Vec::new(),
            bag: HashBag::new(),
            status: TaskStatus::Z,
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
            backend.context_restore(context)
                .expect("[continue_run] failed to restore context");
        }
        let mut pc = backend.reg_read(RegisterARM64::PC)
            .expect("[continue_run] failed to get pc");
        let lr = backend.reg_read(RegisterARM64::LR).unwrap_or(0);
        let x0 = backend.reg_read(RegisterARM64::X0).unwrap_or(0);
        let x8 = backend.reg_read(RegisterARM64::X8).unwrap_or(0);
        // After Halt in a leaf `svc #0`, resume at LR. Returning into the
        // post-SVC CMN/RET of the libc wrapper has been seen to AV the host.
        if lr != 0 && pc >= 4 {
            let mut insn = [0u8; 4];
            if backend.mem_read(pc - 4, &mut insn).is_ok() {
                let w = u32::from_le_bytes(insn);
                if w & 0xffe0_001f == 0xd400_0001 {
                    let _ = backend.reg_write(RegisterARM64::PC, lr);
                    pc = lr;
                }
            }
        }
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
                Waiter::Unknown(_) => {
                    warn!("unknown waiter on can_dispatch, treating as runnable");
                    true
                }
            }
        }
        true
    }

    fn save_context(&mut self, emulator: &AndroidEmulator<'a, T>) {
        let backend = emulator.backend.clone();
        let mut context = if let Some(context) = &self.context {
            context.clone()
        } else {
            let context = backend.context_alloc()
                .expect("failed to save context");
            context
        };
        backend.context_save(&mut context)
            .expect("failed to save context");
        self.context = Some(context);
    }

    fn is_context_saved(&self) -> bool {
        self.context.is_some()
    }

    fn restore_context(&self, emulator: &AndroidEmulator<'a, T>) {
        if let Some(context) = &self.context {
            emulator.backend.context_restore(context)
                .expect("[restore_context] failed to restore context");
        } else {
            warn!("restore context failed, context is None")
        }
    }

    fn destroy(&self, emulator: &AndroidEmulator<'a, T>) {
        if let Some(memory_block) = &self.stack_block {
            memory_block.free(Some(emulator.clone()))
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