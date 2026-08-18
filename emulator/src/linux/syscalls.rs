use std::ascii::AsciiExt;
use std::cell::OnceCell;
use std::ffi::c_long;
use std::fmt::{format, Write as IGNORE};
use std::io::Write;
use std::mem;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use bitflags::Flags;
use bytes::BytesMut;
use log::{error, info, warn};
use crate::backend::{Backend, Permission};
use crate::backend::RegisterARM64;
use crate::backend::RegisterARM64::{*};
use crate::emulator::{AndroidEmulator, AndroidEmulatorInner, HEAP_BASE};
use crate::emulator::signal::{SignalOps, UnixSigSet};
use crate::emulator::thread::{AbstractTask, MarshmallowThread, RunnableTask, Task, TaskStatus, ThreadDispatcher, Waiter, WaiterTrait};
use crate::linux::errno::Errno;
use crate::linux::file_system::{FileIO, FileIOTrait, SeekResult, StMode};
use crate::linux::fs::ByteArrayFileIO;
use crate::linux::fs::cpuinfo::Cpuinfo;
use crate::linux::fs::direction::Direction;
use crate::linux::fs::linux_file::LinuxFileIO;
use crate::linux::fs::maps::Maps;
use crate::linux::fs::meminfo::Meminfo;
use crate::linux::fs::random_boot_id::RandomBootId;
use crate::linux::fs::urandom::URandom;
use crate::linux::PAGE_ALIGN;
use crate::linux::pipe::PipeIO;
use crate::linux::sock::local_socket::LocalSocket;
use crate::linux::structs::{OFlag, prctl, Timespec, Timeval, Timezone, CloneFlag};
use crate::linux::structs::prctl::PrctlOp;
use crate::linux::structs::socket::{Pf, SockType};
use crate::linux::thread::{FutexIndefinitelyWaiter, FutexNanoSleepWaiter};
use crate::pointer::VMPointer;

macro_rules! throw_err {
    ($backend:ident, $emulator:ident, $errno:expr) => {
        let errno = <Errno as Into<i32>>::into($errno);
        $backend.reg_write_i64(RegisterARM64::X0, -(errno as i64)).unwrap();
        $emulator.set_errno(errno).expect("failed to set errno");
        return;
    };
}
macro_rules! ret_u64 {
    ($backend:ident, $X0:expr) => {
        $backend.reg_write(RegisterARM64::X0, $X0).expect("failed to write x0");
    };
}

macro_rules! ret_i32 {
    ($backend:ident, $X0:expr) => {
        $backend.reg_write_i64(RegisterARM64::X0, ($X0 as i64)).expect("failed to write x0");
    };
}

macro_rules! ldr_i32 {
    ($backend:ident, $id:expr) => {
        $backend.reg_read($id).unwrap() as i32
    };
}

macro_rules! ldr_u32 {
    ($backend:ident, $id:expr) => {
        $backend.reg_read_u32($id).unwrap() as u32
    };
}

macro_rules! ldr_u64 {
    ($backend:ident, $id:expr) => {
        $backend.reg_read($id).unwrap()
    };
}

macro_rules! ldr_string {
    ($backend:ident, $id:expr) => {
        $backend.mem_read_c_string(ldr_u64!($backend, $id)).unwrap()
    };
}

pub fn syscall_brk<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let addr = ldr_u64!(backend, X0);
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall brk({})", addr);
    }

    if addr == 0 {
        emulator.inner_mut().brk = HEAP_BASE;
        ret_u64!(backend, HEAP_BASE);
        return;
    }

    if addr % 8 != 0 {
        throw_err!(backend, emulator, Errno::EINVAL.into());
    }

    let brk = emulator.inner_mut().brk;
    if addr > brk {
        backend.mem_map(brk, (addr - brk) as usize, (Permission::READ | Permission::WRITE).bits()).expect("failed to map memory: brk");
    } else if addr < brk {
        backend.mem_unmap(addr, (brk - addr) as usize).expect("failed to unmap memory: brk");
    }
    emulator.inner_mut().brk = addr;

    ret_u64!(backend, addr);
}

pub fn syscall_prctl<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let from = emulator.find_caller_name();
    let op = ldr_u32!(backend, X0);
    let arg2 = ldr_u64!(backend, X1);
    let arg3 = ldr_u64!(backend, X2);
    let arg4 = ldr_u64!(backend, X3);

    const PR_SET_DUMPABLE: u32 = 4;
    const PR_SET_NAME: u32 = 15;
    const PR_GET_NAME: u32 = 16;
    const PR_SET_PTRACER: u32 = 0x59616d61;
    const PR_SET_NO_NEW_PRIVS: u32 = 38;
    const PR_GET_NO_NEW_PRIVS: u32 = 39;
    const PR_SET_VMA: u32 = 0x53564d41;
    const PR_PAC_RESET_KEYS: u32 = 54;
    const PR_SET_TAGGED_ADDR_CTRL: u32 = 55;
    const PR_GET_TAGGED_ADDR_CTRL: u32 = 56;
    const PR_SET_THP_DISABLE: u32 = 41;
    const PR_GET_THP_DISABLE: u32 = 42;
    const PR_SET_MDWE: u32 = 65;
    const PR_GET_MDWE: u32 = 66;

    info!("syscall prctl(op={}, arg2=0x{:x}, arg3=0x{:x}, arg4=0x{:x}) from {}", op, arg2, arg3, arg4, from);

    match op {
        PR_SET_VMA | PR_SET_NAME | PR_GET_NAME | PR_SET_DUMPABLE
        | PR_SET_PTRACER | PR_SET_NO_NEW_PRIVS | PR_GET_NO_NEW_PRIVS
        | PR_PAC_RESET_KEYS | PR_SET_TAGGED_ADDR_CTRL | PR_SET_THP_DISABLE | PR_SET_MDWE => {
            ret_i32!(backend, 0);
        }
        PR_GET_TAGGED_ADDR_CTRL | PR_GET_THP_DISABLE | PR_GET_MDWE => {
            ret_i32!(backend, 0);
        }
        _ => {
            warn!("prctl unhandled op={} from {} => 0", op, from);
            ret_i32!(backend, 0);
        }
    }
}

pub fn syscall_gettimeofday<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    const TV_SIZE: usize = mem::size_of::<Timeval>();
    const TZ_SIZE: usize = mem::size_of::<Timezone>();

    let tv_pointer = emulator.backend.reg_read(X0).unwrap();
    if tv_pointer != 0 {
        let mut buffer = [0u8; TV_SIZE];
        let tv = unsafe {
            &mut *(buffer.as_mut_ptr() as *mut Timeval)
        };
        let now = chrono::Local::now();
        tv.tv_sec = now.timestamp();
        tv.tv_usec = now.timestamp_subsec_nanos() as i64;
        backend.mem_write(tv_pointer, &buffer).unwrap();
    }

    let tz_pointer = emulator.backend.reg_read(X1).unwrap();
    if tz_pointer != 0 {
        let mut buffer = [0u8; TZ_SIZE];
        let tz = unsafe {
            &mut *(buffer.as_mut_ptr() as *mut Timezone)
        };
        tz.tz_dsttime = 0;
        tz.tz_minuteswest = -480;
        backend.mem_write(tz_pointer, &buffer).unwrap();
    }

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall gettimeofday(tv_pointer=0x{:x}, tz_pointer=0x{:x})", tv_pointer, tz_pointer);
    }

    ret_i32!(backend, 0);
}

pub fn syscall_futex<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let uaddr = ldr_u64!(backend, X0);
    let op = ldr_i32!(backend, X1);
    let val = ldr_u32!(backend, X2);
    let timeout = ldr_u64!(backend, X3);
    let uaddr2 = ldr_u64!(backend, X4);
    let val3 = ldr_i32!(backend, X5);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        let lr = emulator.get_lr().unwrap();
        let from_module = emulator.find_caller();
        let from_module = if let Some(from_module_cell) = from_module {
            let module = unsafe { &*from_module_cell.get() };
            module.name.clone() + format!("@0x{:X}", lr - module.base).as_str()
        } else {
            format!("@0x{:X}", lr)
        };
        let mut old = [0u8; 4];
        if backend.mem_read(uaddr, &mut old).is_err() {
            info!("syscall futex(uaddr=0x{:x}, op={}, val={}, timeout=0x{:x}, uaddr2=0x{:x}, val3={}) from {}", uaddr, op, val, timeout, uaddr2, val3, from_module);
        } else {
            let old = u32::from_le_bytes(old);
            info!("syscall futex(uaddr=0x{:x}, op={}, val={}, old={}, timeout=0x{:x}, uaddr2=0x{:x}, val3={}) from {}", uaddr, op, val, old, timeout, uaddr2, val3, from_module);
        }
    }

    let _is_private = (op & 0x80) != 0;
    let cmd = op & 0x7f;
    // Android 16 bionic uses WAIT_BITSET / WAKE_BITSET. Treat them as WAIT / WAKE.
    const FUTEX_WAIT: i32 = 0;
    const FUTEX_WAKE: i32 = 1;
    const FUTEX_REQUEUE: i32 = 3;
    const FUTEX_CMP_REQUEUE: i32 = 4;
    const FUTEX_WAKE_OP: i32 = 5;
    const FUTEX_WAIT_BITSET: i32 = 9;
    const FUTEX_WAKE_BITSET: i32 = 10;
    if cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET {
        let mut old = [0u8; 4];
        if backend.mem_read(uaddr, &mut old).is_err() {
            throw_err!(backend, emulator, Errno::EAGAIN);
        }
        let old = u32::from_le_bytes(old);
        if old != val {
            throw_err!(backend, emulator, Errno::EAGAIN);
        }

        let mtype = val & 0xc000;
        let shared = val & 0x2000;

        let time_spec = if timeout <= 0 {
            Timespec::default()
        } else {
            let mut buffer = [0u8; size_of::<Timespec>()];
            backend.mem_read(timeout, &mut buffer)
                .expect("Failed to read from memory: time_spec");
            let time_spec: &Timespec = unsafe {
                &*(buffer.as_ptr() as *const Timespec)
            };
            time_spec.clone()
        };

        info!(
            "futex wait uaddr=0x{:x} val={} timeout=0x{:x} tasks={}",
            uaddr, val, timeout, emulator.inner_mut().thread_dispatcher.task_counts()
        );

        // Single-task exec: never park the only thread on FUTEX_WAIT.
        if emulator.inner_mut().thread_dispatcher.task_counts() <= 1 {
            throw_err!(backend, emulator, Errno::EAGAIN);
        }

        let running_task = emulator.inner_mut().thread_dispatcher
            .running_task_mut();
        if let Some(running_task_cell) = running_task {
            let waiter = if timeout == 0 {
                Waiter::FutexIndefinite(FutexIndefinitelyWaiter::new(uaddr, val, &emulator.backend))
            } else {
                Waiter::FutexNanoSleep(FutexNanoSleepWaiter::new(uaddr, val, (time_spec.tv_sec * 1000i64 + time_spec.tv_nsec / 1000000i64) as u64, emulator.backend.clone()))
            };
            if option_env!("EMU_LOG") == Some("1") {
                info!("futex: set waiter: {:?}", match &waiter {
                    Waiter::FutexIndefinite(waiter) => waiter.can_dispatch().to_string() + "/",
                    Waiter::FutexNanoSleep(waiter) => waiter.can_dispatch().to_string() + "|",
                    Waiter::Unknown(_) => unreachable!()
                });
            }
            match unsafe { &mut *running_task_cell.get() } {
                AbstractTask::Function64(task) => {
                    task.set_waiter(emulator, waiter);
                }
                AbstractTask::SignalTask(task) => {
                    task.set_waiter(emulator, waiter);
                }
                AbstractTask::MarshmallowThread(task) => {
                    task.set_waiter(emulator, waiter);
                }
                _ => panic!("futex unexpected task type: running_task"),
            }
            emulator.emu_stop(TaskStatus::S).unwrap();
            return;
        } else {
            unreachable!()
        }

        if emulator.inner_mut().thread_dispatcher.task_counts() > 1 {
            emulator.emu_stop(TaskStatus::X).
                expect("failed to stop emulator");
            ret_i32!(backend, Errno::ETIMEDOUT.as_i32());
            return;
        } else {
            ret_i32!(backend, 0);
            return;
        }
    }
    else if cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET {
        let count = emulator.inner_mut().thread_dispatcher.wake_futex(uaddr, val);
        if count > 0 {
            info!("futex: wake {} waiter(s) at 0x{:x}", count, uaddr);
        }
        ret_i32!(backend, count as i32);
        return;
    }
    else if cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE || cmd == FUTEX_WAKE_OP {
        ret_i32!(backend, 0);
        return;
    } else {
        warn!("futex unhandled cmd={} op=0x{:x} => 0", cmd, op);
        ret_i32!(backend, 0);
    }
}

pub fn syscall_clock_gettime<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    static START: OnceLock<Instant> = OnceLock::new();

    let clk_id = ldr_i32!(backend, X0);
    let tp_pointer = ldr_u64!(backend, X1);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall clock_gettime(clk_id={}, tp_pointer=0x{:x})", clk_id, tp_pointer);
    }

    match clk_id {
        0 => { // CLOCK_REALTIME
            if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let mut buffer = [0u8; size_of::<Timeval>()];
                let tv = unsafe { &mut *(buffer.as_mut_ptr() as *mut Timeval) };
                tv.tv_sec = (duration_since_epoch.as_secs() + 8 * 3600) as i64;
                tv.tv_usec = duration_since_epoch.subsec_micros() as i64;
                backend.mem_write(tp_pointer, &buffer).expect("failed to write timeval");
                ret_i32!(backend, 0);
            } else {
                panic!("SystemTime before UNIX EPOCH!");
            }
        }
        1 => { // CLOCK_MONOTONIC
            let start = START.get_or_init(|| Instant::now()).clone();
            let mut buffer = [0u8; size_of::<Timespec>()];
            let duration = Instant::now().duration_since(start);
            let tv = unsafe { &mut *(buffer.as_mut_ptr() as *mut Timespec) };
            tv.tv_sec = duration.as_secs() as i64;
            tv.tv_nsec = duration.subsec_nanos() as i64;
            backend.mem_write(tp_pointer, &buffer).expect("failed to write timespec");
            ret_i32!(backend, 0);
        }
        3 => { // CLOCK_THREAD_CPUTIME_ID
            let start = START.get_or_init(|| Instant::now()).clone();
            let mut buffer = [0u8; size_of::<Timespec>()];
            let duration = Instant::now().duration_since(start);
            let tv = unsafe { &mut *(buffer.as_mut_ptr() as *mut Timespec) };
            tv.tv_sec = 0;
            tv.tv_nsec = duration.subsec_nanos() as i64;
            backend.mem_write(tp_pointer, &buffer).expect("failed to write timespec");
            ret_i32!(backend, 0);
        }
        4 | 6 | 7 => { // CLOCK_MONOTONIC_RAW / COARSE / BOOTTIME
            let start = START.get_or_init(|| Instant::now()).clone();
            let mut buffer = [0u8; size_of::<Timespec>()];
            let duration = Instant::now().duration_since(start);
            let tv = unsafe { &mut *(buffer.as_mut_ptr() as *mut Timespec) };
            tv.tv_sec = duration.as_secs() as i64;
            tv.tv_nsec = duration.subsec_nanos() as i64;
            backend.mem_write(tp_pointer, &buffer).expect("failed to write timespec");
            ret_i32!(backend, 0);
        }
        5 => { // CLOCK_REALTIME_COARSE
            if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let mut buffer = [0u8; size_of::<Timespec>()];
                let tv = unsafe { &mut *(buffer.as_mut_ptr() as *mut Timespec) };
                tv.tv_sec = duration_since_epoch.as_secs() as i64;
                tv.tv_nsec = duration_since_epoch.subsec_nanos() as i64;
                backend.mem_write(tp_pointer, &buffer).expect("failed to write timespec");
                ret_i32!(backend, 0);
            } else {
                throw_err!(backend, emulator, Errno::EINVAL);
            }
        }
        _ => {
            warn!("clock_gettime unsupported clk_id={}, returning EINVAL", clk_id);
            throw_err!(backend, emulator, Errno::EINVAL);
        }
    }
}

pub fn syscall_openat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let dir_fd = ldr_i32!(backend, X0);
    let flags = OFlag::from_bits_truncate(ldr_u32!(backend, X2));
    let mode = ldr_i32!(backend, X3);
    let path_pointer = ldr_u64!(backend, X1);
    let Ok(path) = backend.mem_read_c_string(path_pointer) else {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            error!("openat: failed to read path");
        }
        panic!("failed to read path");
    };

    if path == "/data/misc/zoneinfo/current/tzdata" {
        throw_err!(backend, emulator, Errno::ENOMEM);
    }

    if path == "/dev/pmsg0" {
        throw_err!(backend, emulator, Errno::EPERM);
    }

    if !path.starts_with("/") {
        if dir_fd != -100 {
            if option_env!("EMU_LOG") == Some("1") {
                error!("openat: dir_fd != AT_FDCWD");
            }

            panic!("dir_fd != AT_FDCWD");
        }
    }

    let from_module = emulator.find_caller_name();
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        info!("syscall try openat(path={}, flags={:?}, mode={}) from {}", path, flags, mode, from_module);
    }
    let (fd, errno) = open(emulator, &path, flags, mode, &from_module);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        info!("syscall openat(path={}, flags={:?}, mode={}) -> {} from {}", path, flags, mode, fd, from_module);
    }

    ret_i32!(backend, fd);
    emulator.set_errno(errno).expect("failed to set errno");
    return;
}

pub fn syscall_mmap<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let start = ldr_u64!(backend, X0);
    let length = ldr_i32!(backend, X1) as usize;
    let prot = ldr_i32!(backend, X2);
    let flags = ldr_i32!(backend, X3);
    let fd = ldr_i32!(backend, X4);
    let offset = ldr_i32!(backend, X5) << 12;

    match emulator.mmap2(start, length, prot as u32, flags as u32, fd, offset as i64) {
        Ok((errno, addr)) => {
            if errno != Errno::OK {
                throw_err!(backend, emulator, errno);
            }
            ret_u64!(backend, addr);
            return;
        }
        Err(err) => {
            error!("mmap failed: {:?}", err);
            throw_err!(backend, emulator, Errno::EAGAIN);
        }
    }
}

pub fn syscall_mprotect<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let addr = ldr_u64!(backend, X0);
    let len = ldr_i32!(backend, X1) as usize;
    let prot = ldr_u32!(backend, X2);

    info!("syscall mprotect(addr=0x{:x}, len={}, prot={})", addr, len, prot);

    let aligned_address = (addr / PAGE_ALIGN as u64) * PAGE_ALIGN as u64;
    let offset = addr - aligned_address;
    let size = len + offset as usize;
    let aligned_length = ((size - 1) / PAGE_ALIGN + 1) * PAGE_ALIGN;

/*    let mut mem_map_item = None;
    for (begin, map) in emulator.inner_mut().memory.memory_map.iter() {
        if *begin <= aligned_address && aligned_address < (map.base + map.size as u64) {
            mem_map_item = Some(map.clone());
            break;
        }
    }

    if let Some(mem_map_item) = mem_map_item {
        if mem_map_item.from_file {
            let block_prot = Permission::from_bits_truncate(mem_map_item.prot);
            if !block_prot.contains(Permission::WRITE) && prot.contains(Permission::WRITE) {
                throw_err!(backend, emulator, Errno::EACCES);
            }
            if !block_prot.contains(Permission::READ) && prot.contains(Permission::READ) {
                throw_err!(backend, emulator, Errno::EACCES);
            }
        }
    }*/

    if aligned_address % PAGE_ALIGN as u64 != 0 {
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    if let Err(e) = backend.mem_protect(aligned_address, aligned_length, prot) {
        warn!("mprotect failed: {:?}", e);
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    ret_i32!(backend, 0);
}

pub fn syscall_madvise<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let addr = ldr_u64!(backend, X0);
    let len = ldr_i32!(backend, X1) as usize;
    let advice = ldr_i32!(backend, X2);
    if advice == 4 {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall madvice(addr=0x{:x}, len={}, advice={}) => success", addr, len, advice);
        }

        ret_i32!(backend, 0);
    }

    if addr <= 0 {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall madvice(addr=0x{:x}, len={}, advice={}) => addr is nullptr", addr, len, advice);
        }
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    if addr % PAGE_ALIGN as u64 != 0 {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall madvice(addr=0x{:x}, len={}, advice={}) => addr not aligned", addr, len, advice);
        }
        throw_err!(backend, emulator, Errno::EINVAL);
    }
    if len % PAGE_ALIGN != 0 {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall madvice(addr=0x{:x}, len={}, advice={}) => len is not aligned", addr, len, advice);
        }
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    if let Some(_) = emulator.inner_mut().memory.memory_map.get(&addr) {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall madvice(addr=0x{:x}, len={}, advice={}) => success", addr, len, advice);
        }
        ret_i32!(backend, 0);
    } else {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall madvice(addr=0x{:x}, len={}, advice={}) => locked memory", addr, len, advice);
        }
        throw_err!(backend, emulator, Errno::EINVAL);
    }
}

pub fn syscall_fstat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let stat_pointer = ldr_u64!(backend, X1);
    let file_system = &mut emulator.inner_mut().file_system;

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall fstat(fd={}, stat_pointer=0x{:x})", fd, stat_pointer);
    }

    if let Some(file) = file_system.get_file_mut(fd) {
        match file {
            FileIO::Bytes(file) => {
                file.fstat(VMPointer::new(stat_pointer, 0, backend.clone()));
            }
            FileIO::File(file) => {
                file.fstat(VMPointer::new(stat_pointer, 0, backend.clone()));
            }
            FileIO::Dynamic(file) => {
                file.fstat(VMPointer::new(stat_pointer, 0, backend.clone()));
            }
            FileIO::Error(_) => panic!("fstat error, fd: {}, reason: file not found", fd),
            FileIO::Direction(dir) => {
                dir.fstat(VMPointer::new(stat_pointer, 0, backend.clone()));
            },
            FileIO::LocalSocket(_) => unreachable!()
        }
    } else {
        throw_err!(backend, emulator, Errno::EBADF);
    }
}

pub fn syscall_munmap<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let start = ldr_u64!(backend, X0);
    let length = ldr_i32!(backend, X1) as usize;

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall munmap(start=0x{:x}, length={})", start, length);
    }

    if let Err(e) = emulator.munmap(start, length as u64) {
        warn!("munmap failed: {:?}", e);
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    ret_u64!(backend, 0);
}

pub fn syscall_close<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall close(fd={})", fd);
    }

    if fd < 0 {
        throw_err!(backend, emulator, Errno::EBADF);
    }

    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.remove_file(fd) {
/*        let running_task = emulator.inner_mut().thread_dispatcher
            .running_task_mut();
        let is_main_task = if let Some(running_task_cell) = running_task {
            match unsafe { &mut *running_task_cell.get() } {
                AbstractTask::Function64(_) => true,
                AbstractTask::SignalTask(_) => false,
                AbstractTask::MarshmallowThread(_) => false,
                _ => panic!("close unexpected task type: running_task"),
            }
        } else {
            false
        };*/

        match file {
            FileIO::Bytes(_) => {}
            FileIO::File(mut file) => {
                file.close();
            }
            FileIO::Error(_) => panic!("close error, fd: {}, reason: file not found", fd),
            FileIO::Dynamic(mut file) => {
                file.close();
            }
            FileIO::Direction(_) => {}
            FileIO::LocalSocket(mut socket) => {
                <LocalSocket as FileIOTrait<T>>::close(&mut socket);
            }
        }
    } else {
        throw_err!(backend, emulator, Errno::EBADF);
    }
    ret_i32!(backend, 0);
}

pub fn syscall_read<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let buf = ldr_u64!(backend, X1);
    let count = ldr_i32!(backend, X2) as usize;
    let from_module = emulator.find_caller_name();

    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.get_file_mut(fd) {
        let mode = match file {
            FileIO::Bytes(bytes) => bytes.st_mode(),
            FileIO::File(file) => file.st_mode(),
            FileIO::Error(_) => {
                throw_err!(backend, emulator, Errno::EBADF);
            }
            FileIO::Dynamic(file) => {
                file.st_mode()
            }
            FileIO::Direction(dir) => {
                <Direction as FileIOTrait<T>>::st_mode(dir)
            }
            FileIO::LocalSocket(_) => {
                StMode::S_IRUSR | StMode::S_IWUSR
            }
        };

        if !(mode.contains(StMode::S_IRUSR) || mode.contains(StMode::S_IROTH) || mode.contains(StMode::S_IRGRP)) && from_module != "libc.so" {
            throw_err!(backend, emulator, Errno::EACCES);
        }

        let read = match file {
            FileIO::Bytes(file) => file.read(VMPointer::new(buf, 0, backend.clone()), count),
            FileIO::File(file) => file.read(VMPointer::new(buf, 0, backend.clone()), count),
            FileIO::Error(_) => unreachable!(),
            FileIO::Dynamic(file) => file.read(VMPointer::new(buf, 0, backend.clone()), count),
            FileIO::Direction(_) => unreachable!(),
            FileIO::LocalSocket(socket) => socket.read(VMPointer::new(buf, 0, backend.clone()), count),
        };

        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall read(fd={}, buf=0x{:x}, count={}) => {} from {}", fd, buf, count, read, from_module);
        }

        ret_u64!(backend, read as u64);
    } else {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall read(fd={}, buf=0x{:x}, count={}) => EBADF from {}", fd, buf, count, from_module);
        }

        throw_err!(backend, emulator, Errno::EBADF);
    }
}

pub fn syscall_geteuid<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall geteuid()");
    }

    ret_i32!(backend, 10261);
}

pub fn syscall_renameat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let old_dir_fd = ldr_i32!(backend, X0);
    let old_path_ptr = ldr_u64!(backend, X1);
    let new_dir_fd = ldr_i32!(backend, X2);
    let new_path_ptr = ldr_u64!(backend, X3);

    let old_path = backend.mem_read_c_string(old_path_ptr).unwrap();
    let new_path = backend.mem_read_c_string(new_path_ptr).unwrap();

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        if old_path.is_ascii() && new_path.is_ascii() {
            println!("syscall renameat(old_dir_fd={}, old_path={}, new_dir_fd={}, new_path={})", old_dir_fd, old_path, new_dir_fd, new_path);
        } else {
            println!("syscall renameat(old_dir_fd={}, old_path=hex::decode({}), new_dir={}, new_path=hex::deecode({}))", old_dir_fd, hex::encode(old_path.as_bytes()), new_dir_fd, hex::encode(new_path.as_bytes()));
        }
    }

    if !new_path.is_empty() && new_path.as_bytes()[0] != b'/' {
        throw_err!(backend, emulator, Errno::EROFS);
    }

    unreachable!("renameat not supported");
}

pub fn syscall_fstatat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let path = ldr_string!(backend, X1);
    let stat_pointer = ldr_u64!(backend, X2);
    let flag = ldr_u32!(backend, X3);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        if path.is_ascii() {
            println!("syscall fstatat(fd={}, path={}, stat_pointer=0x{:x}, flag={})", fd, path, stat_pointer, flag);
        } else {
            println!("syscall fstatat(fd={}, path=hex::decode({}), stat_pointer=0x{:x}, flag={})", fd, hex::encode(path.as_bytes()), stat_pointer, flag);
        }
    }

    if path.is_empty() || path.as_bytes()[0] != b'/' {
        throw_err!(backend, emulator, Errno::ENOENT);
    }

    if fd != -100 {
        throw_err!(backend, emulator, Errno::EBADF);
    }

    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(ref resolver) = file_system.file_resolver {
        if let Some(file) = resolver(file_system, path.as_str(), OFlag::from_bits_truncate(flag), 0) {
            match file {
                FileIO::Bytes(file) => file.fstat(VMPointer::new(stat_pointer, 0, backend.clone())),
                FileIO::Error(errno) => {
                    ret_i32!(backend, fd);
                    emulator.set_errno(errno).expect("failed to set errno");
                    return;
                },
                FileIO::File(file) => file.fstat(VMPointer::new(stat_pointer, 0, backend.clone())),
                FileIO::Dynamic(file) => file.fstat(VMPointer::new(stat_pointer, 0, backend.clone())),
                FileIO::Direction(dir) => {
                    dir.fstat(VMPointer::new(stat_pointer, 0, backend.clone()));
                }
                FileIO::LocalSocket(_) => unreachable!()
            }
        } else {
            throw_err!(backend, emulator, Errno::ENOENT);
        }
    } else {
        throw_err!(backend, emulator, Errno::ENOENT);
    }
}

pub fn syscall_getppid<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall getppid()");
    }

    ret_i32!(backend, emulator.inner_mut().ppid as i32);
}

pub fn syscall_getpid<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall getpid()");
    }

    ret_i32!(backend, emulator.inner_mut().pid as i32);
}

pub fn syscall_getuid<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall getuid()");
    }
    ret_i32!(backend, 10261);
}

pub fn syscall_clone<'a, T: Clone>(backend: &Backend<'a, T>, emulator: &AndroidEmulator<'a, T>) {
    // // pid_t __bionic_clone(int flags, void* child_stack, pid_t* parent_tid, void* tls, pid_t* child_tid, int (*fn)(void*), void* arg);
    let child_stack = ldr_u64!(backend, X1);
    let parent_tid = ldr_u32!(backend, X2);

    if child_stack == 0 && parent_tid == 0 {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall clone(child_stack=0, parent_tid=0)");
        }
        syscall_fork(backend, emulator);
        return;
    }

    let fnc = emulator.backend.reg_read(X5).unwrap() as i64;
    let arg = emulator.backend.reg_read(X6).unwrap() as i64;
    if child_stack != 0 {
        let stack_fn = backend.mem_read_i64(child_stack).unwrap_or(0);
        let stack_arg = backend.mem_read_i64(child_stack + 8).unwrap_or(0);
        if stack_fn == fnc && stack_arg == arg && fnc != 0 {
            info!("syscall clone => bionic_clone fn=0x{:x}", fnc);
            syscall_bionic_clone(backend, emulator);
            return;
        }
        if stack_fn != 0 {
            info!("syscall clone => pthread_clone fn=0x{:x}", stack_fn);
            syscall_pthread_clone(backend, emulator, stack_fn as u64, stack_arg as u64);
            return;
        }
    }
    if fnc != 0 {
        info!("syscall clone => bionic_clone (x5) fn=0x{:x}", fnc);
        syscall_bionic_clone(backend, emulator);
        return;
    }
    warn!("clone falling back to fork stub");
    syscall_fork(backend, emulator);
}

pub fn syscall_sigaltstack<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let ss = ldr_u64!(backend, X0);
    let old_ss = ldr_u64!(backend, X1);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall sigaltstack(ss=0x{:x}, old_ss=0x{:x})", ss, old_ss);
    }

    if old_ss != 0 {
        // stack_t { ss_sp, ss_flags, ss_size } — report no alternate stack.
        let _ = backend.mem_write(old_ss, &[0u8; 24]);
    }

    ret_i32!(backend, 0);
}

pub fn syscall_lseek<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let offset = ldr_u64!(backend, X1) as i64;
    let whence = ldr_i32!(backend, X2);


    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.get_file_mut(fd) {
        let result = match file {
            FileIO::Bytes(file) => file.lseek(offset, whence),
            FileIO::File(file) => file.lseek(offset, whence),
            FileIO::Error(_) => unreachable!(),
            FileIO::Dynamic(file) => file.lseek(offset, whence),
            FileIO::Direction(_) => unreachable!(),
            FileIO::LocalSocket(_) => panic!("lseek not supported: local socket"),
        };
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall lseek(fd={}, offset={}, whence={}) => {:?}", fd, offset, whence, result);
        }
        match result {
            SeekResult::Ok(offset) => {
                ret_u64!(backend, offset as u64);
            }
            SeekResult::WhenceError => {
                throw_err!(backend, emulator, Errno::EINVAL);
            }
            SeekResult::OffsetError => {
                throw_err!(backend, emulator, Errno::ENXIO);
            }
            SeekResult::UnknownError => {
                throw_err!(backend, emulator, Errno::ESPIPE);
            }
        }
    } else {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall lseek(fd={}, offset={}, whence={}) => EBADF", fd, offset, whence);
        }
        throw_err!(backend, emulator, Errno::EBADF);
    }
}

pub fn syscall_mkdirat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let dir_fd = ldr_i32!(backend, X0);
    let path = ldr_string!(backend, X1);
    let mode = ldr_u32!(backend, X2);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall mkdirat(dir_fd={}, path={}, mode={:X})", dir_fd, path, mode);
    }

    if path.is_empty() || path.as_bytes()[0] != b'/' {
        throw_err!(backend, emulator, Errno::ENOENT);
    }

    if dir_fd != -100 {
        throw_err!(backend, emulator, Errno::EBADF);
    }

    if path == "/sdcard/Android/" || path == "/sdcard/Android" {
        throw_err!(backend, emulator, Errno::EEXIST);
    }

    throw_err!(backend, emulator, Errno::EACCES);
}

pub fn syscall_set_tid_address<'a, T: Clone>(backend: &Backend<'a, T>, emulator: &AndroidEmulator<'a, T>) {
    let tidptr = ldr_u64!(backend, X0);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        let from = emulator.find_caller_name();
        println!("syscall set_tid_address(tidptr=0x{:x}) from {}", tidptr, from);
    }

    if let Some(task) = emulator.inner_mut().context_task.as_ref() {
        if let AbstractTask::MarshmallowThread(task) = unsafe { &mut *task.get() } {
            task.set_tid_ptr(VMPointer::new(tidptr, 0, backend.clone()));
        }
    }
    ret_u64!(backend, emulator.get_current_pid() as u64);
}

pub fn syscall_rt_sigprocmask<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let how = ldr_i32!(backend, X0);
    let set = ldr_u64!(backend, X1);
    let oldset = ldr_u64!(backend, X2);

    let from = emulator.find_caller_name();
    let lr = emulator.get_lr().unwrap_or(0);
    info!("syscall rt_sigprocmask(how={}, set=0x{:x}, oldset=0x{:x}) from {} lr=0x{:x}", how, set, oldset, from, lr);

    let task = emulator.inner_mut().context_task.as_ref().unwrap();
    match unsafe { &mut *task.get() } {
        AbstractTask::MarshmallowThread(task) => {
            let ops = task.signal_ops_mut();
            let old = ops.get_sig_mask_set();
            if oldset != 0 {
                if let Some(ref old) = old {
                    let mask = old.get_mask();
                    backend.mem_write(oldset, &mask.to_le_bytes()).unwrap();
                }
            }

            if set == 0 {
                ret_i32!(backend, 0);
                return;
            }

            let mask = backend.mem_read_u64(set).unwrap();
            match how {
                0 => {
                    if old.is_none() {
                        let set = UnixSigSet::new(mask);
                        let pending_set = UnixSigSet::new(0);
                        ops.set_sig_mask_set(Box::new(set));
                        ops.set_sig_pending_set(Box::new(pending_set));
                    } else {
                        old.unwrap().block_sig_set(mask);
                    }
                    ret_i32!(backend, 0);
                    return;
                }
                1 => {
                    if old.is_some() {
                        old.unwrap().unblock_sig_set(mask);
                    }
                    ret_i32!(backend, 0);
                    return;
                }
                2 => {
                    let set = UnixSigSet::new(mask);
                    let pending_set = UnixSigSet::new(0);
                    ops.set_sig_mask_set(Box::new(set));
                    ops.set_sig_pending_set(Box::new(pending_set));
                    ret_i32!(backend, 0);
                    return;
                }
                _ => {
                    warn!("rt_sigprocmask unsupported how={}", how);
                    throw_err!(backend, emulator, Errno::EINVAL);
                }
            }
        }
        _ => {
            if oldset != 0 {
                let _ = backend.mem_write(oldset, &0u64.to_le_bytes());
            }
            ret_i32!(backend, 0);
            return;
        }
    }
}

pub fn syscall_rt_sigaction<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let signum = ldr_i32!(backend, X0);
    let act = ldr_u64!(backend, X1);
    let oldact = ldr_u64!(backend, X2);
    info!("syscall rt_sigaction(sig={}, act=0x{:x}, oldact=0x{:x})", signum, act, oldact);
    if oldact != 0 {
        // struct sigaction { sa_handler, sa_flags, sa_mask... } — report SIG_DFL
        let _ = backend.mem_write(oldact, &[0u8; 32]);
    }
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_rt_sigtimedwait<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let info = ldr_u64!(backend, X1);
    info!("syscall rt_sigtimedwait info=0x{:x} => SIGINT", info);
    if info != 0 {
        // siginfo_t.si_signo / si_code
        let _ = backend.mem_write(info, &2i32.to_le_bytes());
        let _ = backend.mem_write(info + 8, &0i32.to_le_bytes());
    }
    let _ = emulator;
    ret_i32!(backend, 2);
}

pub fn syscall_wait4<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let pid = ldr_i32!(backend, X0);
    info!("syscall wait4/waitid(pid={}) => ECHILD", pid);
    let _ = emulator;
    throw_err!(backend, emulator, Errno::ECHILD);
}

pub fn syscall_kill<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let pid = ldr_i32!(backend, X0);
    let sig = ldr_i32!(backend, X1);
    info!("syscall kill/tkill(pid={}, sig={}) => 0", pid, sig);
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_rt_tgsigqueueinfo<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let tgid = ldr_i32!(backend, X0);
    let tid = ldr_i32!(backend, X1);
    let sig = ldr_i32!(backend, X2);
    info!("syscall rt_tgsigqueueinfo(tgid={}, tid={}, sig={})", tgid, tid, sig);
    let _ = emulator;
    // Pretend the signal was queued. Real delivery is not implemented.
    ret_i32!(backend, 0);
}

pub fn syscall_exit<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let status = ldr_i32!(backend, X0);

    let task = emulator.inner_mut().context_task.as_ref().unwrap();
    match unsafe { &mut *task.get() } {
        AbstractTask::MarshmallowThread(task) => {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                println!("syscall exit(status={}) by ThreadTask", status);
            }
            let ctid = task.child_tid_addr();
            task.set_exit_status(status);
            // CLONE_CHILD_CLEARTID: write 0 (in set_exit_status) then wake joiners.
            if ctid != 0 {
                let _ = emulator.inner_mut().thread_dispatcher.wake_futex(ctid, u32::MAX);
            }
            emulator.emu_stop(TaskStatus::X).unwrap();
            return;
        }
        _ => {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                println!("syscall exit(status={}) by main task", status);
            }
            emulator.inner_mut().exit_status = Some(status);
            flush_bionic_stdio(backend, emulator);
            crate::terminate_host(status);
        }
    }
}

pub fn syscall_exit_group<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let status = ldr_i32!(backend, X0);
    let lr = emulator.get_lr().unwrap_or(0);
    let caller = emulator.find_caller_name();
    warn!("syscall exit_group(status={}) lr=0x{:x} from {}", status, lr, caller);
    emulator.inner_mut().exit_status = Some(status);
    flush_bionic_stdio(backend, emulator);
    // Do not return into the JIT or run CRT teardown.
    crate::terminate_host(status);
}

pub fn syscall_bionic_clone<'a, T: Clone>(backend: &Backend<'a, T>, emulator: &AndroidEmulator<'a, T>) {
    let flag = ldr_u32!(backend, X0);
    let child_stack = ldr_u64!(backend, X1);
    let parent_tid = ldr_u64!(backend, X2);
    let tls = ldr_u64!(backend, X3);
    let child_tid = ldr_u64!(backend, X4);
    let fn_ptr = ldr_u64!(backend, X5);
    let arg = ldr_u64!(backend, X6);

    let flag = CloneFlag::from_bits_truncate(flag);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall bionic_clone(flag={:?}, child_stack=0x{:x}, parent_tid=0x{:x}, tls=0x{:x}, child_tid=0x{:x}, fn=0x{:x}, arg=0x{:x})", flag, child_stack, parent_tid, tls, child_tid, fn_ptr, arg);
    }

    if !flag.contains(CloneFlag::CLONE_VM) || !flag.contains(CloneFlag::CLONE_THREAD) {
        warn!("bionic_clone without CLONE_VM|CLONE_THREAD, treating as thread anyway");
    }

    let thread_id = emulator.inner_mut().task_id_factory
        .fetch_add(1, Ordering::SeqCst);

    if flag.contains(CloneFlag::CLONE_PARENT_SETTID) {
        if parent_tid == 0 {
            throw_err!(backend, emulator, Errno::EINVAL);
        }
        backend.mem_write(parent_tid, &thread_id.to_le_bytes()).unwrap();
    }

    //println!("bbbbbbbbbbbb");
    let thread = AbstractTask::MarshmallowThread(MarshmallowThread::new(
        emulator.clone(),
        thread_id,
        VMPointer::new(fn_ptr, 0, backend.clone()),
        VMPointer::new(arg, 0, backend.clone()),
        Some(VMPointer::new(child_tid, 0, backend.clone())),
        tls,
        child_stack,
    ));
    //println!("ddddddddddd");
    emulator.inner_mut().thread_dispatcher.add_thread(thread);
    //println!("cccccc");

    if child_tid != 0 {
        backend.mem_write(child_tid, &thread_id.to_le_bytes()).unwrap();
    }
    ret_i32!(backend, thread_id as i32);
}

pub fn syscall_pthread_clone<'a, T: Clone>(
    backend: &Backend<'a, T>,
    emulator: &AndroidEmulator<'a, T>,
    fn_ptr: u64,
    arg: u64,
) {
    let child_tid = ldr_u64!(backend, X4);
    let thread_id = emulator
        .inner_mut()
        .task_id_factory
        .fetch_add(1, Ordering::SeqCst);
    let parent_tid = ldr_u64!(backend, X2);
    if parent_tid != 0 {
        let _ = backend.mem_write(parent_tid, &thread_id.to_le_bytes());
    }
    let tls = ldr_u64!(backend, X3);
    let child_stack = ldr_u64!(backend, X1);
    let thread = AbstractTask::MarshmallowThread(MarshmallowThread::new(
        emulator.clone(),
        thread_id,
        VMPointer::new(fn_ptr, 0, backend.clone()),
        VMPointer::new(arg, 0, backend.clone()),
        if child_tid != 0 {
            Some(VMPointer::new(child_tid, 0, backend.clone()))
        } else {
            None
        },
        tls,
        child_stack,
    ));
    emulator.inner_mut().thread_dispatcher.add_thread(thread);
    if child_tid != 0 {
        let _ = backend.mem_write(child_tid, &thread_id.to_le_bytes());
    }
    info!("pthread_clone started tid={} fn=0x{:x}", thread_id, fn_ptr);
    ret_i32!(backend, thread_id as i32);
}

#[inline]
pub fn syscall_fork<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    // Pretend the parent survived and the child vanished. Constructors that
    // probe clone/fork then keep running in the parent.
    let child = emulator.inner_mut().pid.saturating_add(1000) as i32;
    warn!("fork is stubbed: returning child pid {}", child);
    ret_i32!(backend, child);
}

pub fn syscall_faccessat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let dir_fd = ldr_i32!(backend, X0);
    let path = ldr_string!(backend, X1);
    let mode = ldr_i32!(backend, X2);
    let flag = ldr_i32!(backend, X3);

    info!("syscall faccessat(dir_fd={}, path={}, mode={}, flag={})", dir_fd, path, mode, flag);

    if !path.is_ascii() {
        throw_err!(backend, emulator, Errno::ENOENT);
    }

    if path == "/dev/null" || path == "/dev/urandom" || path == "/dev/zero"
        || path == "/proc/self/maps" || path == "/proc/meminfo" || path == "/proc/cpuinfo"
        || path == "/proc/stat" || path == "/proc/self/exe"
    {
        ret_i32!(backend, 0);
        return;
    }

    if path == "/data/data/com.tencent.mobileqq" {
        ret_i32!(backend, 0);
        return;
    }

    if path.starts_with("/vendor")
        || path.contains("/su")
        || path.starts_with("/proc/rk_")
        || path.starts_with("/proc/device-tree")
        || path.starts_with("/proc/mpp_service")
        || path.starts_with("/sys/bus/platform/drivers/hisi-lpc")
        || path == "/hmdocker"
        || path == "/dev/__properties__"
    {
        throw_err!(backend, emulator, Errno::ENOENT);
    }

    if path.starts_with('/') {
        let host = Path::new(&emulator.inner_mut().base_path).join(path.trim_start_matches('/'));
        if host.exists() {
            ret_i32!(backend, 0);
            return;
        }
    }

    throw_err!(backend, emulator, Errno::ENOENT);
}

pub fn syscall_getdents64<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let dirp = ldr_u64!(backend, X1);
    let size = ldr_i32!(backend, X2) as usize;

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall getdents64(fd={}, dirp=0x{:x}, size={})", fd, dirp, size);
    }

    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.get_file_mut(fd) {
        let ret = match file {
            FileIO::Bytes(_) => unreachable!(),
            FileIO::File(_) => unreachable!(),
            FileIO::Error(_) => unreachable!(),
            FileIO::Dynamic(_) => unreachable!(),
            FileIO::Direction(dir) => dir.getdents64(VMPointer::new(dirp, 0, backend.clone()), size),
            FileIO::LocalSocket(_) => unreachable!()
        };

        ret_u64!(backend, ret as u64);
    } else {
        throw_err!(backend, emulator, Errno::EBADF);
    }
}

pub fn syscall_write<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let buf = ldr_u64!(backend, X1);
    let count = ldr_i32!(backend, X2) as usize;

    let from_module = emulator.find_caller_name();
    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.get_file_mut(fd) {
        let mode = match file {
            FileIO::Bytes(bytes) => bytes.st_mode(),
            FileIO::File(file) => file.st_mode(),
            FileIO::Error(_) => {
                throw_err!(backend, emulator, Errno::EBADF);
            }
            FileIO::Dynamic(file) => file.st_mode(),
            FileIO::Direction(_) => unreachable!(),
            FileIO::LocalSocket(_) => {
                StMode::S_IRUSR | StMode::S_IWUSR
            }
        };

        if !(mode.contains(StMode::S_IWUSR) || mode.contains(StMode::S_IWOTH) || mode.contains(StMode::S_IWGRP)) && from_module != "libc.so" {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                println!("syscall write(fd={}, buf=0x{:x}, count={}) => EACCES from {}", fd, buf, count, from_module);
            }
            throw_err!(backend, emulator, Errno::EACCES);
        }

        let data = backend.mem_read_as_vec(buf, count).unwrap();

        let written = match file {
            FileIO::Bytes(file) => file.write(data.as_slice()),
            FileIO::File(file) => file.write(data.as_slice()),
            FileIO::Error(_) => unreachable!(),
            FileIO::Dynamic(file) => file.write(data.as_slice()),
            FileIO::Direction(_) => unreachable!(),
            FileIO::LocalSocket(socket) => {
                <LocalSocket as FileIOTrait<T>>::write(socket, data.as_slice())
            },
        };

        if written == -1 {
            throw_err!(backend, emulator, Errno::EACCES);
        }

        if fd <= 2 || option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            info!("syscall write(fd={}, count={}) => {} from {}", fd, count, written, from_module);
        }

        ret_u64!(backend, written as u64);
    } else {
        if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
            println!("syscall write(fd={}, buf=0x{:x}, count={}) => EBADF from {}", fd, buf, count, from_module);
        }

        throw_err!(backend, emulator, Errno::EBADF);
    }
}

pub fn syscall_socket<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let domain = Pf::from_u32(ldr_u32!(backend, X0));
    let typ = SockType::from_bits_truncate(ldr_u32!(backend, X1));
    let protocol = ldr_i32!(backend, X2);

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall socket(domain={:?}, type={:?}, protocol={})", domain, typ, protocol);
    }

    let file_system = &mut emulator.inner_mut().file_system;
    if domain == Pf::LOCAL {
        let fd = file_system.insert_file(FileIO::LocalSocket(LocalSocket::new()));
        ret_i32!(backend, fd);
        return;
    }

    throw_err!(backend, emulator, Errno::EAFNOSUPPORT);
}

pub fn syscall_connect<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let sock_fd = ldr_i32!(backend, X0);
    let addr = ldr_u64!(backend, X1);
    let addr_len = ldr_i32!(backend, X2) as usize;
    let from = emulator.find_caller_name();

    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall connect(sock_fd={}, addr=0x{:x}, addr_len={}) from {}", sock_fd, addr, addr_len, from);
    }

    if from == "libc.so" {
        throw_err!(backend, emulator, Errno::EACCES);
    }

    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.get_file_mut(sock_fd) {
        match file {
            FileIO::LocalSocket(socket) => {
                let ret = socket.connect(VMPointer::new(addr, 0, backend.clone()), addr_len, emulator);
                ret_i32!(backend, ret);
                return;
            }
            _ => {
                throw_err!(backend, emulator, Errno::ENOTSOCK);
            }
        }
    } else {
        throw_err!(backend, emulator, Errno::EBADF);
    }

    unreachable!()
}

pub fn syscall_pipe2<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let pipefd = ldr_u64!(backend, X0);
    let flags = ldr_i32!(backend, X1);
    info!("syscall pipe2(pipefd=0x{:x}, flags={})", pipefd, flags);
    let (reader, writer) = crate::linux::pipe::PipeIO::pair();
    let file_system = &mut emulator.inner_mut().file_system;
    let rfd = file_system.insert_file(FileIO::Dynamic(Box::new(reader)));
    let wfd = file_system.insert_file(FileIO::Dynamic(Box::new(writer)));
    let _ = backend.mem_write(pipefd, &rfd.to_le_bytes());
    let _ = backend.mem_write(pipefd + 4, &wfd.to_le_bytes());
    ret_i32!(backend, 0);
}

pub fn syscall_nanosleep<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let rem = ldr_u64!(backend, X1);
    if rem != 0 {
        let _ = backend.mem_write(rem, &[0u8; 16]);
    }
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_sched_yield<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_sched_getaffinity<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let cpusetsize = (ldr_u64!(backend, X1) as usize).min(128);
    let mask = ldr_u64!(backend, X2);
    if mask != 0 && cpusetsize > 0 {
        let mut bits = vec![0u8; cpusetsize];
        bits[0] = 1; // CPU 0
        let _ = backend.mem_write(mask, &bits);
    }
    let _ = emulator;
    ret_i32!(backend, cpusetsize.min(8) as i32);
}

pub fn syscall_sched_setaffinity<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_statfs<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let path = ldr_string!(backend, X0);
    let buf = ldr_u64!(backend, X1);
    info!("syscall statfs(path={}, buf=0x{:x})", path, buf);
    if buf != 0 {
        // struct statfs on aarch64 is 120 bytes. Fake a 4K ext4.
        let mut st = [0u8; 120];
        st[0..8].copy_from_slice(&0xEF53u64.to_le_bytes()); // f_type EXT4
        st[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
        st[16..24].copy_from_slice(&262144u64.to_le_bytes()); // f_blocks
        st[24..32].copy_from_slice(&131072u64.to_le_bytes()); // f_bfree
        st[32..40].copy_from_slice(&131072u64.to_le_bytes()); // f_bavail
        st[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
        st[72..80].copy_from_slice(&4096u64.to_le_bytes()); // f_frsize
        let _ = backend.mem_write(buf, &st);
    }
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_nr3264_fcntl<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    const F_DUPFD: i32 = 0;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const F_DUPFD_CLOEXEC: i32 = 1030;

    let fd = ldr_i32!(backend, X0);
    let cmd = ldr_i32!(backend, X1);
    let arg = ldr_u64!(backend, X2);

    let file_system = &mut emulator.inner_mut().file_system;
    let Some(file) = file_system.get_file_mut(fd) else {
        throw_err!(backend, emulator, Errno::EBADF);
    };

    match cmd {
        F_GETFD | F_SETFD => {
            ret_i32!(backend, 0);
        }
        F_GETFL => {
            let flags = match file {
                FileIO::Bytes(f) => f.oflags().bits(),
                FileIO::File(f) => f.oflags().bits(),
                FileIO::Dynamic(f) => f.oflags().bits(),
                FileIO::Direction(_) => 0,
                FileIO::LocalSocket(_) => 0,
                FileIO::Error(_) => {
                    throw_err!(backend, emulator, Errno::EBADF);
                }
            };
            ret_u64!(backend, flags as u64);
        }
        F_SETFL => {
            ret_i32!(backend, 0);
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let _ = (file, arg);
            throw_err!(backend, emulator, Errno::ENOSYS);
        }
        _ => {
            if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
                println!("syscall fcntl(fd={}, cmd={}, arg=0x{:x}) => 0", fd, cmd, arg);
            }
            ret_i32!(backend, 0);
        }
    }
}

pub fn syscall_enosys<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>, nr: crate::emulator::syscall_handler::Syscalls) {
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall {:?} => ENOSYS", nr);
    } else {
        warn!("unimplemented syscall {:?} => ENOSYS", nr);
    }
    throw_err!(backend, emulator, Errno::ENOSYS);
}

pub fn syscall_writev<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let iov = ldr_u64!(backend, X1);
    let iovcnt = ldr_i32!(backend, X2);
    if iovcnt < 0 {
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    if iovcnt > 1024 {
        throw_err!(backend, emulator, Errno::EINVAL);
    }

    let mut total = 0i64;
    for i in 0..iovcnt as u64 {
        let base = backend.mem_read_u64(iov + i * 16).unwrap_or(0);
        let len = (backend.mem_read_u64(iov + i * 16 + 8).unwrap_or(0) as usize).min(1 << 20);
        if len == 0 {
            continue;
        }
        let data = backend.mem_read_as_vec(base, len).unwrap_or_default();
        let file_system = &mut emulator.inner_mut().file_system;
        let Some(file) = file_system.get_file_mut(fd) else {
            throw_err!(backend, emulator, Errno::EBADF);
        };
        let written = match file {
            FileIO::Bytes(f) => f.write(&data),
            FileIO::File(f) => f.write(&data),
            FileIO::Dynamic(f) => f.write(&data),
            FileIO::LocalSocket(s) => <LocalSocket as FileIOTrait<T>>::write(s, &data),
            FileIO::Direction(_) | FileIO::Error(_) => {
                throw_err!(backend, emulator, Errno::EBADF);
            }
        };
        if written < 0 {
            throw_err!(backend, emulator, Errno::EACCES);
        }
        total += written as i64;
    }
    ret_i32!(backend, total as i32);
}

pub fn syscall_uname<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let buf = ldr_u64!(backend, X0);
    // struct utsname { char[65] sysname, nodename, release, version, machine, domainname }
    const FIELD: usize = 65;
    let mut data = vec![0u8; FIELD * 6];
    let fields = [
        "Linux",
        "localhost",
        "6.6.0-android16-0",
        "#1 SMP PREEMPT",
        "aarch64",
        "localdomain",
    ];
    for (i, field) in fields.iter().enumerate() {
        let start = i * FIELD;
        let bytes = field.as_bytes();
        data[start..start + bytes.len()].copy_from_slice(bytes);
    }
    if backend.mem_write(buf, &data).is_err() {
        throw_err!(backend, emulator, Errno::EFAULT);
    }
    ret_i32!(backend, 0);
}

pub fn syscall_gettid<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    ret_u64!(backend, emulator.get_current_pid() as u64);
}

pub fn syscall_getcwd<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let buf = ldr_u64!(backend, X0);
    let size = ldr_u64!(backend, X1) as usize;
    let cwd = b"/data/local/tmp\0";
    if size < cwd.len() {
        throw_err!(backend, emulator, Errno::ERANGE);
    }
    if backend.mem_write(buf, cwd).is_err() {
        throw_err!(backend, emulator, Errno::EFAULT);
    }
    ret_u64!(backend, buf);
}

pub fn syscall_readlinkat<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let _dirfd = ldr_i32!(backend, X0);
    let path = ldr_string!(backend, X1);
    let buf = ldr_u64!(backend, X2);
    let bufsiz = ldr_u64!(backend, X3) as usize;

    let target = if path == "/proc/self/exe" || path.starts_with("/proc/self/exe") {
        emulator
            .inner_mut()
            .exec_path
            .clone()
            .unwrap_or_else(|| format!("/system/bin/{}", emulator.inner_mut().proc_name))
    } else {
        throw_err!(backend, emulator, Errno::ENOENT);
    };

    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsiz);
    if backend.mem_write(buf, &bytes[..n]).is_err() {
        throw_err!(backend, emulator, Errno::EFAULT);
    }
    ret_i32!(backend, n as i32);
}

pub fn syscall_dup3<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let oldfd = ldr_i32!(backend, X0);
    let newfd = ldr_i32!(backend, X1);
    if oldfd == newfd {
        ret_i32!(backend, newfd);
        return;
    }
    // Minimal: succeed without remapping; enough for close-on-exec probes.
    let _ = emulator;
    ret_i32!(backend, newfd);
}

pub fn syscall_getrandom<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let buf = ldr_u64!(backend, X0);
    let buflen = (ldr_u64!(backend, X1) as usize).min(1 << 16);
    let _flags = ldr_u32!(backend, X2);
    let mut data = vec![0u8; buflen];
    for b in data.iter_mut() {
        *b = rand::random::<u8>();
    }
    if backend.mem_write(buf, &data).is_err() {
        throw_err!(backend, emulator, Errno::EFAULT);
    }
    ret_u64!(backend, buflen as u64);
}

pub fn syscall_ioctl<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let fd = ldr_i32!(backend, X0);
    let cmd = ldr_u32!(backend, X1);
    let arg = ldr_u64!(backend, X2);
    const TCGETS: u32 = 0x5401;
    const TIOCGWINSZ: u32 = 0x5413;
    const TIOCGPGRP: u32 = 0x540F;
    if option_env!("PRINT_SYSCALL_LOG") == Some("1") {
        println!("syscall ioctl(fd={}, cmd=0x{:x}, arg=0x{:x})", fd, cmd, arg);
    }
    let _ = emulator;
    // Report stdio as a tty so bionic line-buffers stdout. Then a
    // printf("…\n") issues write(1) before exit_group.
    if fd >= 0 && fd <= 2 {
        match cmd {
            TCGETS => {
                if arg != 0 {
                    let _ = backend.mem_write(arg, &[0u8; 64]);
                }
                ret_i32!(backend, 0);
                return;
            }
            TIOCGWINSZ => {
                if arg != 0 {
                    let mut ws = [0u8; 8];
                    ws[0..2].copy_from_slice(&24u16.to_le_bytes());
                    ws[2..4].copy_from_slice(&80u16.to_le_bytes());
                    let _ = backend.mem_write(arg, &ws);
                }
                ret_i32!(backend, 0);
                return;
            }
            TIOCGPGRP => {
                if arg != 0 {
                    let _ = backend.mem_write(arg, &2667i32.to_le_bytes());
                }
                ret_i32!(backend, 0);
                return;
            }
            _ => {}
        }
    }
    throw_err!(backend, emulator, Errno::ENOTTY);
}

/// Drain bionic `FILE` write buffers.
/// API 36 FILE is 152 bytes (BSD `__sFILE`):
/// `_p`@0, `_flags`@16, `_file`@20, `_bf._base`@24. `__sglue` walks the list
/// (`next`@0, `niobs`@8, `iobs`@16) the same way `fflush_all` does.
fn flush_bionic_stdio<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    const __SWR: i32 = 0x0008;
    let libc = {
        let memory = &emulator.inner_mut().memory;
        memory.modules.get("libc.so").cloned()
    };
    let Some(cell) = libc else {
        return;
    };
    let module = unsafe { &*cell.get() };
    if let Ok(sym) = module.find_symbol_by_name("__sglue", false) {
        flush_sglue_chain(backend, emulator, sym.address());
    }
    for name in ["stdout", "stderr"] {
        let Ok(sym) = module.find_symbol_by_name(name, false) else {
            continue;
        };
        let Ok(maybe_ptr) = backend.mem_read_u64(sym.address()) else {
            continue;
        };
        let fp = if maybe_ptr > 0x10000 && backend.mem_read_u64(maybe_ptr).is_ok() {
            maybe_ptr
        } else {
            sym.address()
        };
        flush_one_file(backend, emulator, fp);
    }
}

fn flush_sglue_chain<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>, mut glue: u64) {
    for _ in 0..8 {
        if glue == 0 {
            break;
        }
        let Ok(niobs) = backend.mem_read_i32(glue + 8) else {
            break;
        };
        let Ok(iobs) = backend.mem_read_u64(glue + 16) else {
            break;
        };
        if iobs != 0 && niobs > 0 && niobs < 64 {
            for i in 0..niobs as u64 {
                flush_one_file(backend, emulator, iobs + i * 152);
            }
        }
        let Ok(next) = backend.mem_read_u64(glue) else {
            break;
        };
        if next == glue {
            break;
        }
        glue = next;
    }
}

fn flush_one_file<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>, fp: u64) {
    const __SWR: i32 = 0x0008;
    let Ok(p) = backend.mem_read_u64(fp) else {
        return;
    };
    let Ok(flags) = backend.mem_read_i32(fp + 16) else {
        return;
    };
    if flags == 0 || flags & 0x8000 != 0 || flags & __SWR == 0 {
        return;
    }
    let Ok(file_no) = backend.mem_read_i32(fp + 20) else {
        return;
    };
    let Ok(base) = backend.mem_read_u64(fp + 24) else {
        return;
    };
    if p == 0 || base == 0 || p < base {
        return;
    }
    let n = p.saturating_sub(base) as usize;
    if n == 0 || n > 1 << 20 {
        return;
    }
    let Ok(buf) = backend.mem_read_as_vec(base, n) else {
        return;
    };
    write_guest_fd(emulator, file_no, &buf);
    let _ = backend.mem_write(fp, &base.to_le_bytes());
    info!("flushed FILE fp=0x{:x} fd={} {} bytes", fp, file_no, n);
}

fn write_guest_fd<T: Clone>(emulator: &AndroidEmulator<T>, fd: i32, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let file_system = &mut emulator.inner_mut().file_system;
    if let Some(file) = file_system.get_file_mut(fd) {
        match file {
            FileIO::Bytes(f) => {
                let _ = f.write(data);
            }
            FileIO::File(f) => {
                let _ = f.write(data);
            }
            FileIO::Dynamic(f) => {
                let _ = f.write(data);
            }
            FileIO::LocalSocket(s) => {
                let _ = <LocalSocket as FileIOTrait<T>>::write(s, data);
            }
            FileIO::Error(_) | FileIO::Direction(_) => {}
        }
    }
}

pub fn syscall_set_robust_list<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_rseq<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_membarrier<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    let _ = emulator;
    ret_i32!(backend, 0);
}

pub fn syscall_statx<T: Clone>(backend: &Backend<T>, emulator: &AndroidEmulator<T>) {
    throw_err!(backend, emulator, Errno::ENOSYS);
}

#[inline]
fn open<T: Clone>(emulator: &AndroidEmulator<T>, path: &str, flags: OFlag, mode: i32, from_module: &str) -> (i32, i32) {
    if path == "/dev/__properties__" {
        let errno: i32 = Errno::EPERM.into();
        return (-errno, errno);
    }

    let file_system = &mut emulator.inner_mut().file_system;
    if path == "/dev/urandom" {
        let fd = file_system.insert_file(FileIO::Dynamic(Box::new(
            URandom::new(path, flags.bits(), 0, StMode::SYSTEM_FILE)
        )));
        return (fd, 0)
    } else if path == "/proc/meminfo" {
        let fd = file_system.insert_file(FileIO::Dynamic(Box::new(
            Meminfo::new(path, flags.bits())
        )));
        return (fd, 0)
    } else if path == "/proc/cpuinfo" {
        let fd = file_system.insert_file(FileIO::Dynamic(Box::new(
            Cpuinfo::new(path, flags.bits())
        )));
        return (fd, 0)
    } else if path == "/proc/sys/kernel/random/boot_id" {
        let fd = file_system.insert_file(FileIO::Dynamic(Box::new(
            RandomBootId::new(path, flags.bits())
        )));
        return (fd, 0)
    }

    if path == "/proc/stat" {
        return if from_module == "libc.so" {
            // 8个cpu?
            let mut buf = BytesMut::new();
            buf.write_str("cpu 9160 11352 15848 9160 11352 1584 80 0 0 0").unwrap();
            for i in 0..8 {
                buf.write_str(format!("cpu{} 1145 1419 1981 1145 1419 198 10 0 0 0", i).as_str()).unwrap();
            }
            let bytes_file = ByteArrayFileIO::new(buf.freeze().to_vec(), path.to_string(), 0, flags.bits(), StMode::SYSTEM_FILE);
            let fd = file_system.insert_file(FileIO::Bytes(bytes_file));
            (fd, 0)
        } else {
            let errno: i32 = Errno::EPERM.into();
            (-errno, errno)
        }
    }

    if let Some(ref resolver) = file_system.file_resolver {
        if let Some(file) = resolver(file_system, path, flags, mode) {
            return match file {
                FileIO::Bytes(file) => {
                    let fd = file_system.insert_file(FileIO::Bytes(file));
                    (fd, 0)
                }
                FileIO::Error(errno) => (-errno, errno),
                FileIO::File(file) => {
                    let fd = file_system.insert_file(FileIO::File(file));
                    (fd, 0)
                }
                FileIO::Dynamic(file) => {
                    let fd = file_system.insert_file(FileIO::Dynamic(file));
                    (fd, 0)
                }
                FileIO::Direction(dir) => {
                    let fd = file_system.insert_file(FileIO::Direction(dir));
                    (fd, 0)
                }
                FileIO::LocalSocket(_) => unreachable!()
            }
        }
    }

    if path == "/proc/self/maps" {
        let fd = file_system.insert_file(FileIO::Dynamic(Box::new(
            Maps::new(path, flags.bits())
        )));
        return (fd, 0)
    }

    if path == "/dev/null" {
        let fd = file_system.insert_file(FileIO::Bytes(ByteArrayFileIO::new(
            Vec::new(),
            path.to_string(),
            0,
            flags.bits(),
            StMode::SYSTEM_FILE,
        )));
        return (fd, 0)
    }

    // Map guest absolute paths onto the pulled SDK tree (BASE_PATH).
    if path.starts_with('/') {
        let host = Path::new(&emulator.inner_mut().base_path).join(path.trim_start_matches('/'));
        if host.is_file() {
            if let Some(host_str) = host.to_str() {
                let file_system = &mut emulator.inner_mut().file_system;
                let fd = file_system.insert_file(FileIO::File(LinuxFileIO::new(
                    host_str,
                    path,
                    flags.bits(),
                    0,
                    StMode::SYSTEM_FILE,
                )));
                return (fd, 0);
            }
        }
    }

    let errno: i32 = Errno::ENOENT.into();
    (-errno, errno)
}
