use crate::emulator::AndroidEmulator;
use crate::pointer::VMPointer;
use anyhow::anyhow;
use log::{error, info};
use std::marker::PhantomData;

#[derive(Clone)]
pub(crate) enum InitFunction<'a, T: Clone> {
    ABSOLUTE(AbsoluteInitFunction<'a, T>),
    LINUX(LinuxInitFunction<'a, T>),
}

pub(crate) trait InitFunctionTrait<'a, T: Clone> {
    fn addr(&self) -> u64;

    fn call(&self, emu: AndroidEmulator<'a, T>) -> anyhow::Result<u64>;
}

#[derive(Clone)]
pub(crate) struct AbsoluteInitFunction<'a, T: Clone> {
    pub load_base: u64,
    pub lib_name: String,
    pub addr: u64,
    pub ptr: VMPointer<'a, T>,
}

impl<'a, T: Clone> AbsoluteInitFunction<'a, T> {
    pub fn new(
        load_base: u64,
        lib_name: String,
        ptr: VMPointer<'a, T>,
    ) -> anyhow::Result<AbsoluteInitFunction<'a, T>> {
        let addr = ptr.read_u64_with_offset(0)?;
        Ok(Self {
            load_base,
            lib_name,
            addr,
            ptr,
        })
    }
}

impl<'a, T: Clone> InitFunctionTrait<'a, T> for AbsoluteInitFunction<'a, T> {
    fn addr(&self) -> u64 {
        self.addr
    }

    fn call(&self, emu: AndroidEmulator<'a, T>) -> anyhow::Result<u64> {
        let mut address = self.ptr.read_u64_with_offset(0)?;
        if address == 0 {
            address = self.addr;
        }

        if address == 0 || address == u64::MAX {
            return Ok(0);
        }

        info!(
            "[{}] CallInitFunction: addr=0x{:X}, offset=0x{:X}",
            self.lib_name,
            address,
            address.saturating_sub(self.load_base)
        );
        match emu.e_func(address, vec![]) {
            Some(ret) => Ok(ret),
            None => {
                error!(
                    "[{}] init 0x{:x} did not finish; continuing",
                    self.lib_name, address
                );
                Ok(0)
            }
        }

        //info!("CallInitFunction: addr=0x{:X}", address);
    }
}

#[derive(Clone)]
pub(crate) struct LinuxInitFunction<'a, T: Clone> {
    pub load_base: u64,
    #[allow(unused)]
    pub lib_name: String,
    pub addr: u64,
    pd: PhantomData<&'a T>,
}

impl<'a, T: Clone> LinuxInitFunction<'a, T> {
    pub fn new(load_base: u64, lib_name: String, addr: u64) -> LinuxInitFunction<'a, T> {
        Self {
            load_base,
            lib_name,
            addr,
            pd: PhantomData,
        }
    }
}

impl<'a, T: Clone> InitFunctionTrait<'a, T> for LinuxInitFunction<'a, T> {
    fn addr(&self) -> u64 {
        self.addr + self.load_base
    }

    fn call(&self, emu: AndroidEmulator<'a, T>) -> anyhow::Result<u64> {
        if self.addr == 0 || self.addr() == u64::MAX {
            return Ok(0);
        }

        info!("[{}] CallInitFunction: addr=0x{:X}", self.lib_name, self.addr());
        emu.e_func(self.addr(), vec![]);

        Ok(self.addr)
    }
}
