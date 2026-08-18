use crate::emulator::VMPointer;
use crate::linux::file_system::{FileIOTrait, SeekResult, StMode, SEEK_CUR, SEEK_END, SEEK_SET};
use crate::linux::structs::OFlag;
use std::io::{self, Write};

/// Guest stdin (fd 0). Reads report EOF so binaries that probe stdin do not block.
pub struct StdinIO {
    oflags: u32,
}

impl StdinIO {
    pub fn new() -> Self {
        Self {
            oflags: OFlag::O_RDONLY.bits(),
        }
    }
}

impl<T: Clone> FileIOTrait<T> for StdinIO {
    fn close(&mut self) {}

    fn read(&mut self, _buf: VMPointer<T>, _count: usize) -> usize {
        0
    }

    fn pread(&mut self, _buf: VMPointer<T>, _count: usize, _offset: usize) -> usize {
        0
    }

    fn write(&mut self, _buf: &[u8]) -> i32 {
        -1
    }

    fn lseek(&mut self, offset: i64, whence: i32) -> SeekResult {
        match whence {
            SEEK_SET | SEEK_CUR | SEEK_END => SeekResult::Ok(offset.max(0)),
            _ => SeekResult::WhenceError,
        }
    }

    fn path(&self) -> &str {
        "stdin"
    }

    fn oflags(&self) -> OFlag {
        OFlag::from_bits_truncate(self.oflags)
    }

    fn st_mode(&self) -> StMode {
        StMode::S_IFCHR | StMode::S_IRUSR | StMode::S_IRGRP | StMode::S_IROTH
    }

    fn uid(&self) -> i32 {
        0
    }

    fn len(&self) -> usize {
        0
    }

    fn to_vec(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

/// Guest stdout / stderr. Writes are forwarded to the host stream.
pub struct StdoutIO {
    path: &'static str,
    err: bool,
    oflags: u32,
}

impl StdoutIO {
    pub fn stdout() -> Self {
        Self {
            path: "stdout",
            err: false,
            oflags: OFlag::O_WRONLY.bits(),
        }
    }

    pub fn stderr() -> Self {
        Self {
            path: "stderr",
            err: true,
            oflags: OFlag::O_WRONLY.bits(),
        }
    }
}

impl<T: Clone> FileIOTrait<T> for StdoutIO {
    fn close(&mut self) {}

    fn read(&mut self, _buf: VMPointer<T>, _count: usize) -> usize {
        0
    }

    fn pread(&mut self, _buf: VMPointer<T>, _count: usize, _offset: usize) -> usize {
        0
    }

    fn write(&mut self, buf: &[u8]) -> i32 {
        let _ = if self.err {
            let mut out = io::stderr().lock();
            out.write_all(buf)
        } else {
            let mut out = io::stdout().lock();
            let r = out.write_all(buf);
            let _ = out.flush();
            r
        };
        buf.len() as i32
    }

    fn lseek(&mut self, offset: i64, whence: i32) -> SeekResult {
        match whence {
            SEEK_SET | SEEK_CUR | SEEK_END => SeekResult::Ok(offset.max(0)),
            _ => SeekResult::WhenceError,
        }
    }

    fn path(&self) -> &str {
        self.path
    }

    fn oflags(&self) -> OFlag {
        OFlag::from_bits_truncate(self.oflags)
    }

    fn st_mode(&self) -> StMode {
        StMode::S_IFCHR | StMode::S_IWUSR | StMode::S_IWGRP | StMode::S_IWOTH
    }

    fn uid(&self) -> i32 {
        0
    }

    fn len(&self) -> usize {
        0
    }

    fn to_vec(&mut self) -> Vec<u8> {
        Vec::new()
    }
}
