//! Loader output: the firmware console and COM1, in parallel.
//!
//! Both, because each covers the other's blind spot. The firmware console is the
//! only thing visible on a machine with no serial port — which is most laptops —
//! but it disappears at `ExitBootServices`, and it cannot be captured into a
//! file. COM1 survives the transition, is what QEMU logs, and is the channel the
//! kernel itself comes up on, so the loader's last line and the kernel's first
//! land in the same stream where their order is evidence.
//!
//! Writing to a dead console must not fault: after `ExitBootServices` the
//! firmware pointer is cleared with [`Console::firmware_is_gone`], and everything
//! afterwards goes to serial alone.

use core::fmt::{self, Write};

use staros_arch_x86_64::serial::Uart16550;
use staros_hal::SerialConsole;

use crate::efi::SimpleTextOutput;

/// How many UCS-2 code units are buffered before a flush to the firmware. Small
/// on purpose: it lives on the stack, and the firmware call is not cheap enough
/// to make per-character output reasonable.
const UCS2_CHUNK: usize = 96;

/// A `core::fmt` sink writing to the firmware console and COM1 at once.
pub struct Console {
    /// `ConOut`, or null once boot services are gone.
    out: *mut SimpleTextOutput,
    uart: Uart16550,
    have_serial: bool,
}

impl Console {
    /// Bind to the firmware console and probe COM1.
    ///
    /// # Safety
    /// `out` must be the live `ConOut` pointer from the system table, or null.
    pub unsafe fn new(out: *mut SimpleTextOutput) -> Self {
        let uart = Uart16550::com1();
        // SAFETY: the loader is the only thing driving COM1 at this point;
        // firmware may have configured it, and reconfiguring is harmless.
        let have_serial = unsafe { uart.init() };
        Self { out, uart, have_serial }
    }

    /// Forget the firmware console. Called immediately after `ExitBootServices`,
    /// before anything else can try to print through a pointer whose backing code
    /// has just been invalidated.
    pub fn firmware_is_gone(&mut self) {
        self.out = core::ptr::null_mut();
    }

    /// Whether a serial port answered the loopback probe.
    #[must_use]
    pub const fn have_serial(&self) -> bool {
        self.have_serial
    }

    /// Push one UCS-2 chunk to the firmware console.
    fn flush_ucs2(&mut self, buf: &mut [u16; UCS2_CHUNK + 1], len: &mut usize) {
        if *len == 0 || self.out.is_null() {
            *len = 0;
            return;
        }
        buf[*len] = 0;
        // SAFETY: `out` is non-null here, so it is the firmware's live ConOut;
        // `buf` is NUL-terminated within its own storage, which is what
        // OutputString requires.
        unsafe {
            ((*self.out).output_string)(self.out, buf.as_ptr());
        }
        *len = 0;
    }

    /// Emit one character to serial immediately and to the firmware buffer,
    /// flushing that buffer when it fills.
    fn emit(&mut self, c: char, buf: &mut [u16; UCS2_CHUNK + 1], len: &mut usize) {
        if self.have_serial {
            let mut utf8 = [0u8; 4];
            for b in c.encode_utf8(&mut utf8).as_bytes() {
                self.uart.write_byte(*b);
            }
        }
        // Anything outside the Basic Multilingual Plane is not a single UCS-2
        // code unit. The loader prints ASCII, so substituting is enough — and
        // better than truncating the line that was about to explain a failure.
        let unit = u32::from(c);
        buf[*len] = if unit <= 0xFFFF { unit as u16 } else { u16::from(b'?') };
        *len += 1;
        if *len == UCS2_CHUNK {
            self.flush_ucs2(buf, len);
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = [0u16; UCS2_CHUNK + 1];
        let mut len = 0usize;

        for ch in s.chars() {
            // Both channels want CRLF: the firmware console treats a bare LF as
            // "down one line, same column", and a serial terminal agrees.
            if ch == '\n' {
                self.emit('\r', &mut buf, &mut len);
            }
            self.emit(ch, &mut buf, &mut len);
        }

        self.flush_ucs2(&mut buf, &mut len);
        Ok(())
    }
}
