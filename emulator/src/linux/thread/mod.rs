use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::backend::{Backend, RegisterARM64};
use crate::emulator::AndroidEmulator;
use crate::emulator::signal::SignalTask;
use crate::emulator::thread::{WaiterTrait};
use crate::linux::errno::Errno;

/// Unlock a bionic mutex word left behind by an exited thread.
/// `val & 3 != 0` is the locked/contended encoding; the next word is `__owner`.
fn unlock_stale_futex<T: Clone>(backend: &Backend<T>, uaddr: u64, val: u32) {
    let mut old = [0u8; 4];
    if backend.mem_read(uaddr, &mut old).is_err() {
        return;
    }
    if u32::from_le_bytes(old) != val {
        return;
    }
    let _ = backend.mem_write(uaddr, &0u32.to_le_bytes());
    if val & 3 != 0 {
        let _ = backend.mem_write(uaddr.wrapping_add(4), &0u32.to_le_bytes());
    }
}

pub struct FutexIndefinitelyWaiter<'a, T: Clone> {
    uaddr: u64,
    val: u32,
    woken_up: bool,
    backend: Backend<'a, T>
}

impl<'a, T: Clone> FutexIndefinitelyWaiter<'a, T> {
    pub fn new(uaddr: u64, val: u32, backend: &Backend<'a, T>) -> Self {
        Self {
            uaddr,
            val,
            woken_up: false,
            backend: backend.clone()
        }
    }

    pub fn wake_up(&mut self, addr: u64) -> bool {
        if addr == self.uaddr {
            self.woken_up = true;
            return true;
        }
        false
    }

    pub fn release_for_deadlock(&mut self) -> bool {
        self.woken_up = true;
        unlock_stale_futex(&self.backend, self.uaddr, self.val);
        true
    }
}

impl<'a, T: Clone> WaiterTrait<'a, T> for FutexIndefinitelyWaiter<'a, T> {
    fn can_dispatch(&self) -> bool {
        if self.woken_up {
            return true
        }
        let mut old = [0u8; 4];
        if self.backend.mem_read(self.uaddr, &mut old).is_err() {
            return true;
        }
        let val = u32::from_le_bytes(old);
        val != self.val
    }

    fn on_continue_run(&self, emulator: &AndroidEmulator<'a, T>) {
        if self.woken_up {
            self.backend.reg_write(RegisterARM64::X0, 0).expect("failed to write X0");
        } else {
            let errno: i32 = Errno::EAGAIN.into();
            self.backend.reg_write_i32(RegisterARM64::X0, -errno).expect("failed to write X0: EAGAIN");
        }
    }

    fn on_signal(&self, task: &SignalTask<'a, T>) {
    }
}

pub struct FutexNanoSleepWaiter<'a, T: Clone> {
    uaddr: u64,
    val: u32,
    woken_up: bool,
    wait_millis: u64,
    start_time: u64,
    backend: Backend<'a, T>
}

impl<'a, T: Clone> FutexNanoSleepWaiter<'a, T> {
    pub fn new(uaddr: u64, val: u32, wait_millis: u64, backend: Backend<'a, T>) -> Self {
        let start_time = if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
            duration_since_epoch.as_secs()
        } else {
            panic!("SystemTime before UNIX EPOCH!");
        };
        Self {
            uaddr,
            val,
            wait_millis,
            start_time,
            backend,
            woken_up: false
        }
    }

    pub fn wake_up(&mut self, addr: u64) -> bool {
        if addr == self.uaddr {
            self.woken_up = true;
            return true;
        }
        false
    }

    pub fn release_for_deadlock(&mut self) -> bool {
        self.woken_up = true;
        unlock_stale_futex(&self.backend, self.uaddr, self.val);
        true
    }
}

impl<'a, T: Clone> WaiterTrait<'a, T> for FutexNanoSleepWaiter<'a, T> {
    fn can_dispatch(&self) -> bool {
        if self.woken_up {
            return true
        }
        let mut old = [0u8; 4];
        if self.backend.mem_read(self.uaddr, &mut old).is_err() {
            return true;
        }
        let val = u32::from_le_bytes(old);
        if val != self.val {
            return true;
        }

        let time_millis_now = if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
            duration_since_epoch.as_secs()
        } else {
            panic!("SystemTime before UNIX EPOCH!");
        };
        if time_millis_now - self.start_time >= self.wait_millis {
            return true
        }

        false
    }

    fn on_continue_run(&self, emulator: &AndroidEmulator<'a, T>) {
        if self.woken_up {
            self.backend.reg_write(RegisterARM64::X0, 0).expect("failed to write X0");
        } else {
            let errno: i32 = Errno::ETIMEDOUT.into();
            self.backend.reg_write_i32(RegisterARM64::X0, -errno).expect("failed to write X0: ETIMEDOUT");
        }
    }

    fn on_signal(&self, task: &SignalTask<'a, T>) {
    }
}

fn pipe_unread(buf: &Rc<RefCell<Vec<u8>>>, pos: &Rc<RefCell<usize>>) -> usize {
    let len = buf.borrow().len();
    let p = *pos.borrow();
    len.saturating_sub(p)
}

pub struct PipeReadWaiter<'a, T: Clone> {
    buf: Rc<RefCell<Vec<u8>>>,
    read_pos: Rc<RefCell<usize>>,
    dst: u64,
    count: usize,
    backend: Backend<'a, T>,
    yielded: Cell<bool>,
}

impl<'a, T: Clone> PipeReadWaiter<'a, T> {
    pub fn new(
        buf: Rc<RefCell<Vec<u8>>>,
        read_pos: Rc<RefCell<usize>>,
        dst: u64,
        count: usize,
        backend: Backend<'a, T>,
    ) -> Self {
        Self { buf, read_pos, dst, count, backend, yielded: Cell::new(false) }
    }
}

impl<'a, T: Clone> WaiterTrait<'a, T> for PipeReadWaiter<'a, T> {
    fn can_dispatch(&self) -> bool {
        if pipe_unread(&self.buf, &self.read_pos) > 0 {
            return true;
        }
        if self.yielded.get() {
            return true;
        }
        self.yielded.set(true);
        false
    }

    fn on_continue_run(&self, _emulator: &AndroidEmulator<'a, T>) {
        let data = self.buf.borrow();
        let mut pos = self.read_pos.borrow_mut();
        if *pos >= data.len() {
            let _ = self.backend.reg_write(RegisterARM64::X0, 0);
            return;
        }
        let n = self.count.min(data.len() - *pos);
        let _ = self.backend.mem_write(self.dst, &data[*pos..*pos + n]);
        *pos += n;
        let _ = self.backend.reg_write(RegisterARM64::X0, n as u64);
    }

    fn on_signal(&self, _task: &SignalTask<'a, T>) {}
}

pub struct PollWatch {
    events: i16,
    revents_off: u64,
    buf: Option<(Rc<RefCell<Vec<u8>>>, Rc<RefCell<usize>>)>,
}

pub struct PollWaiter<'a, T: Clone> {
    watches: Vec<PollWatch>,
    backend: Backend<'a, T>,
    yielded: Cell<bool>,
}

impl PollWatch {
    pub fn new(
        events: i16,
        revents_off: u64,
        buf: Option<(Rc<RefCell<Vec<u8>>>, Rc<RefCell<usize>>)>,
    ) -> Self {
        Self { events, revents_off, buf }
    }
}

impl<'a, T: Clone> PollWaiter<'a, T> {
    pub fn new(watches: Vec<PollWatch>, backend: Backend<'a, T>) -> Self {
        Self { watches, backend, yielded: Cell::new(false) }
    }
}

impl<'a, T: Clone> WaiterTrait<'a, T> for PollWaiter<'a, T> {
    fn can_dispatch(&self) -> bool {
        const POLLIN: i16 = 0x1;
        let ready = self.watches.iter().any(|w| {
            if w.events & POLLIN == 0 {
                return false;
            }
            w.buf.as_ref().map(|(b, p)| pipe_unread(b, p) > 0).unwrap_or(false)
        });
        if ready {
            return true;
        }
        if self.yielded.get() {
            return true;
        }
        self.yielded.set(true);
        false
    }

    fn on_continue_run(&self, _emulator: &AndroidEmulator<'a, T>) {
        const POLLIN: i16 = 0x1;
        let mut ready = 0i64;
        for w in &self.watches {
            let mut revents: i16 = 0;
            if w.events & POLLIN != 0 {
                if w.buf.as_ref().map(|(b, p)| pipe_unread(b, p) > 0).unwrap_or(false) {
                    revents = POLLIN;
                    ready += 1;
                }
            }
            let _ = self.backend.mem_write(w.revents_off, &revents.to_le_bytes());
        }
        let _ = self.backend.reg_write_i64(RegisterARM64::X0, ready);
    }

    fn on_signal(&self, _task: &SignalTask<'a, T>) {}
}

pub struct ChildExitWaiter {
    alive: Rc<Cell<bool>>,
    status: Rc<Cell<i32>>,
    pid: i32,
    wstatus: u64,
}

impl ChildExitWaiter {
    pub fn new(pid: i32, wstatus: u64, alive: Rc<Cell<bool>>, status: Rc<Cell<i32>>) -> Self {
        Self { alive, status, pid, wstatus }
    }

    pub fn alive(&self) -> bool {
        self.alive.get()
    }
}

impl<'a, T: Clone> WaiterTrait<'a, T> for ChildExitWaiter {
    fn can_dispatch(&self) -> bool {
        !self.alive.get()
    }

    fn on_continue_run(&self, emulator: &AndroidEmulator<'a, T>) {
        let st = (self.status.get() & 0xff) << 8;
        if self.wstatus != 0 {
            let _ = emulator.backend.mem_write(self.wstatus, &st.to_le_bytes());
        }
        let _ = emulator.backend.reg_write_i32(RegisterARM64::X0, self.pid);
    }

    fn on_signal(&self, _task: &SignalTask<'a, T>) {}
}