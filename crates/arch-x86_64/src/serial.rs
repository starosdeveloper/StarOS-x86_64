//! A 16550-compatible UART on the legacy COM1 ports.
//!
//! The PC's equivalent of the PL011 in the aarch64 tree, with one important
//! difference: **a modern PC may not have one at all.** Laptops dropped the
//! physical port years ago, so on real hardware the framebuffer is the primary
//! console and this is the fallback. Under QEMU it is the reverse — `-serial`
//! output is what a test harness can grep — so both channels are first-class and
//! the console mirrors to whichever exist, exactly as `console.rs` does on
//! aarch64.
//!
//! The register set is unchanged since 1987 and needs no discovery: the ports are
//! fixed by the platform, which is why this is the one device the kernel may
//! touch before parsing a single ACPI table.

use staros_hal::SerialConsole;

use crate::port::{inb, outb};

/// COM1's base I/O port. Fixed by the PC platform since the original AT.
pub const COM1: u16 = 0x3F8;

// Register offsets from the base port. With DLAB clear, offsets 0 and 1 are the
// data and interrupt-enable registers; with DLAB set they are the two halves of
// the baud divisor — the same address meaning two things, which is why the DLAB
// dance below is ordered the way it is.
const DATA: u16 = 0;
const INT_ENABLE: u16 = 1;
const DIVISOR_LO: u16 = 0;
const DIVISOR_HI: u16 = 1;
const FIFO_CTRL: u16 = 2;
const LINE_CTRL: u16 = 3;
const MODEM_CTRL: u16 = 4;
const LINE_STATUS: u16 = 5;

/// `LINE_CTRL` bit 7: the next accesses to offsets 0/1 are the baud divisor.
const LCR_DLAB: u8 = 0x80;
/// 8 data bits, no parity, one stop bit — "8N1", what every terminal expects.
const LCR_8N1: u8 = 0x03;
/// `LINE_STATUS` bit 5: the transmit holding register is empty.
const LSR_THR_EMPTY: u8 = 0x20;
/// `MODEM_CTRL`: data-terminal-ready + request-to-send + auxiliary output 2,
/// the last of which gates the UART's interrupt line onto the bus.
const MCR_DTR_RTS_OUT2: u8 = 0x0B;
/// `MODEM_CTRL`: loopback, plus the same lines — used only to probe.
const MCR_LOOPBACK: u8 = 0x1E;

/// A 16550 UART at a fixed I/O port.
#[derive(Clone, Copy)]
pub struct Uart16550 {
    base: u16,
}

impl Uart16550 {
    /// COM1 at its architectural port.
    #[must_use]
    pub const fn com1() -> Self {
        Self { base: COM1 }
    }

    /// A UART at an arbitrary base port.
    ///
    /// # Safety
    /// `base` must be the base of a 16550-compatible UART. Programming these
    /// registers on something else writes to unknown hardware.
    #[must_use]
    pub const unsafe fn at(base: u16) -> Self {
        Self { base }
    }

    /// Initialise the UART for 115200 8N1 and report whether one is really there.
    ///
    /// The probe is the point. A PC without a serial port does not fault when you
    /// write these ports — the reads simply come back `0xFF`, and a console that
    /// believes in it discards every diagnostic it will ever produce. So the last
    /// step puts the chip in **loopback** and checks that a byte written comes
    /// back: present hardware echoes it, absent hardware does not.
    ///
    /// # Safety
    /// Must be called with exclusive access to this UART's ports, before any
    /// other code drives them.
    pub unsafe fn init(&self) -> bool {
        // SAFETY: the caller guarantees exclusive access to a 16550 at `base`.
        unsafe {
            outb(self.base + INT_ENABLE, 0x00); // no interrupts: we poll
            outb(self.base + LINE_CTRL, LCR_DLAB); // divisor next
            outb(self.base + DIVISOR_LO, 0x01); // 115200 = 115200 / 1
            outb(self.base + DIVISOR_HI, 0x00);
            outb(self.base + LINE_CTRL, LCR_8N1); // clears DLAB again
            outb(self.base + FIFO_CTRL, 0xC7); // FIFOs on, cleared, 14-byte trigger
            outb(self.base + MODEM_CTRL, MCR_LOOPBACK);

            // Loopback probe: what goes out must come back.
            outb(self.base + DATA, 0xAE);
            let echoed = inb(self.base + DATA);

            // Leave the chip in its working configuration whatever the answer, so
            // a false negative costs diagnostics rather than a wedged UART.
            outb(self.base + MODEM_CTRL, MCR_DTR_RTS_OUT2);
            echoed == 0xAE
        }
    }

    /// Whether the transmit holding register can take another byte.
    fn can_send(&self) -> bool {
        // SAFETY: reading the line-status register has no side effects on the
        // transmit path.
        unsafe { inb(self.base + LINE_STATUS) & LSR_THR_EMPTY != 0 }
    }
}

impl SerialConsole for Uart16550 {
    fn write_byte(&self, byte: u8) {
        // Bounded rather than a bare `while`: on hardware that answered the
        // loopback probe but then stopped draining, early boot must not hang in
        // the console. Losing a byte is recoverable; losing the machine is not.
        let mut spins = 0u32;
        while !self.can_send() && spins < 100_000 {
            core::hint::spin_loop();
            spins += 1;
        }
        // SAFETY: writing the data register of a UART we initialised.
        unsafe { outb(self.base + DATA, byte) };
    }
}
