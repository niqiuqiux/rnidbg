use crate::emulator::VMPointer;
use crate::linux::file_system::{FileIOTrait, SeekResult, StMode};
use crate::linux::structs::OFlag;
use std::cell::RefCell;
use std::rc::Rc;

/// Shared in-memory pipe. Both ends hold the same buffer.
#[derive(Clone)]
pub struct PipeIO {
    buf: Rc<RefCell<Vec<u8>>>,
    read_pos: Rc<RefCell<usize>>,
    writer: bool,
    path: String,
    oflags: u32,
}

impl PipeIO {
    pub fn pair() -> (Self, Self) {
        let buf = Rc::new(RefCell::new(Vec::new()));
        let read_pos = Rc::new(RefCell::new(0usize));
        let reader = Self {
            buf: buf.clone(),
            read_pos: read_pos.clone(),
            writer: false,
            path: "pipe:[r]".into(),
            oflags: OFlag::O_RDONLY.bits(),
        };
        let writer = Self {
            buf,
            read_pos,
            writer: true,
            path: "pipe:[w]".into(),
            oflags: OFlag::O_WRONLY.bits(),
        };
        (reader, writer)
    }
}

impl<T: Clone> FileIOTrait<T> for PipeIO {
    fn close(&mut self) {}

    fn read(&mut self, buf: VMPointer<T>, count: usize) -> usize {
        if self.writer {
            return 0;
        }
        let data = self.buf.borrow();
        let mut pos = self.read_pos.borrow_mut();
        if *pos >= data.len() {
            return 0;
        }
        let n = count.min(data.len() - *pos);
        let _ = buf.write_buf(data[*pos..*pos + n].to_vec());
        *pos += n;
        n
    }

    fn pread(&mut self, buf: VMPointer<T>, count: usize, _offset: usize) -> usize {
        self.read(buf, count)
    }

    fn write(&mut self, buf: &[u8]) -> i32 {
        if !self.writer {
            return -1;
        }
        self.buf.borrow_mut().extend_from_slice(buf);
        buf.len() as i32
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> SeekResult {
        SeekResult::UnknownError
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn pipe_reader_bufs(&self) -> Option<(Rc<RefCell<Vec<u8>>>, Rc<RefCell<usize>>)> {
        if self.writer {
            None
        } else {
            Some((self.buf.clone(), self.read_pos.clone()))
        }
    }

    fn oflags(&self) -> OFlag {
        OFlag::from_bits_truncate(self.oflags)
    }

    fn st_mode(&self) -> StMode {
        StMode::S_IFCHR | StMode::S_IRUSR | StMode::S_IWUSR
    }

    fn uid(&self) -> i32 {
        0
    }

    fn len(&self) -> usize {
        self.buf.borrow().len()
    }

    fn to_vec(&mut self) -> Vec<u8> {
        self.buf.borrow().clone()
    }
}
