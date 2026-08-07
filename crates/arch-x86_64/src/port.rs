//! I/O port space.
//!
//! x86 has a second address space besides memory, 16 bits wide, reached only by
//! the `in`/`out` instructions. Nothing else in this kernel's world has one —
//! aarch64 reaches every device through memory-mapped registers — which is why
//! this module has no counterpart in the sibling tree and why the HAL cannot
//! abstract it: there is nothing on the other side to abstract to.
//!
//! It is needed anyway, because the two devices a PC is guaranteed to have at
//! boot live here: the legacy UART ([`crate::serial`]) and the 8259 PICs that
//! must be masked before the APICs can be trusted.

use core::arch::asm;

/// Write a byte to an I/O port.
///
/// # Safety
/// Writing an arbitrary port is arbitrary hardware access: it can reconfigure a
/// device, mask an interrupt line, or on some chipsets power the machine off.
/// The caller must know what is at `port`.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller guarantees the port is one it may write.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// Read a byte from an I/O port.
///
/// # Safety
/// Reads are not free of effects: many device registers clear a condition when
/// read. The caller must know what is at `port`.
#[inline]
#[must_use]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees the port is one it may read.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Write a byte to the unused port `0x80`, the traditional way to spend a bus
/// cycle.
///
/// Old chipsets need settling time between programming steps (the 8259s are the
/// classic case) and have no status bit to poll. Port `0x80` is the POST-code
/// port: writing it is harmless, and the write takes a full, slow ISA-era bus
/// cycle. A delay expressed as work the bus must actually perform is more
/// reliable than one expressed as a loop count the CPU is free to run faster
/// than.
#[inline]
pub fn io_wait() {
    // SAFETY: port 0x80 is the POST-code port; writing it has no effect on any
    // machine this kernel will run on.
    unsafe { outb(0x80, 0) };
}

/// Access to the I/O port space, as a trait rather than as three free functions.
///
/// The legacy chips programmed through this space — the 8259s, the 8254 — are
/// configured by writing magic bytes to fixed ports in a fixed order, and every
/// byte means something different depending on where it falls in the sequence.
/// None of that is visible from outside: the chips accept whatever they are
/// given, and a wrong control word shows up as an interrupt that never arrives,
/// somewhere else, later.
///
/// Behind a trait, the sequence becomes ordinary data. The host tests assert on
/// the exact writes in the exact order, which is the only form in which the
/// mistake is legible.
///
/// # Safety
/// Implementors must direct reads and writes to the real port space, or to a
/// faithful model of it. Callers assume a write has taken effect before the call
/// returns.
pub unsafe trait PortIo {
    /// Write one byte to a port.
    fn write(&mut self, port: u16, value: u8);
    /// Read one byte from a port.
    fn read(&mut self, port: u16) -> u8;
    /// Spend a bus cycle, for chips that need settling time and offer no status
    /// bit to poll. See [`io_wait`].
    fn wait(&mut self);
}

/// The real port space.
pub struct Ports;

// SAFETY: these are the I/O port instructions themselves, and `io_wait` writes
// the POST-code port, which no machine this kernel runs on reacts to.
unsafe impl PortIo for Ports {
    fn write(&mut self, port: u16, value: u8) {
        // SAFETY: the ports reached through this type belong to the drivers that
        // hold it, and each of them names the registers it programs.
        unsafe { outb(port, value) };
    }
    fn read(&mut self, port: u16) -> u8 {
        // SAFETY: as above.
        unsafe { inb(port) }
    }
    fn wait(&mut self) {
        io_wait();
    }
}
