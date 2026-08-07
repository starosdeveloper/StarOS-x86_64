//! The 8254 programmable interval timer, in the smallest form that is useful.
//!
//! This is not the kernel's timer. That is the local APIC's, calibrated against
//! the HPET, and it arrives in phase 2.3. What the PIT is good for right now is
//! being the one device on a PC that can be made to raise a hardware interrupt
//! with two `out` instructions and no discovery, no ACPI table and no driver —
//! which makes it the only way to prove that the 8259 remap in phase 2.1
//! actually took.
//!
//! That proof cannot come from the chips themselves. The 8259's initialisation
//! words are write-only: the mask register reads back, and the vector base does
//! not. "Are interrupts now arriving on vector 32 instead of vector 8" is a
//! question only a delivered interrupt can answer, so the boot arranges for one.
//!
//! Channel 0 is the only channel here. Channel 1 was DRAM refresh and does not
//! exist on anything modern; channel 2 drives the speaker and is wired to a
//! gate the kernel would have to enable first.

use crate::port::PortIo;

/// Data port of channel 0, whose output is wired to IRQ 0.
pub const CHANNEL0_DATA: u16 = 0x40;
/// The mode/command register.
pub const COMMAND: u16 = 0x43;

/// The crystal, in hertz: 1.193182 MHz, or a third of the original NTSC colour
/// burst. Every PC still has it because every PC still pretends to be a PC.
pub const BASE_HZ: u32 = 1_193_182;

/// Command byte: channel 0, access mode lobyte/hibyte, mode 2, binary counting.
///
/// Mode 2 is the rate generator — it reloads and fires again forever, which is
/// what a periodic tick needs. Mode 0 would fire once. The lobyte/hibyte access
/// mode is what makes the divisor two writes rather than one, and both must go
/// out before the channel restarts.
const CMD_CHANNEL0_RATE_LOHI: u8 = 0b0011_0100;

/// Largest divisor the chip can hold. Written as zero, because the counter is 16
/// bits and 65536 does not fit in it — a fencepost the hardware chose.
pub const MAX_DIVISOR: u32 = 65536;

/// The divisor that comes closest to `hz`, clamped to what the counter can hold.
///
/// Returned separately from the programming so the arithmetic can be checked
/// without a chip: a divisor that silently truncated to zero would ask for
/// 18.2 Hz instead of the 1000 Hz that was requested, and the only symptom would
/// be a clock running fifty times slow.
#[must_use]
pub const fn divisor_for(hz: u32) -> u32 {
    if hz == 0 {
        return MAX_DIVISOR;
    }
    let divisor = BASE_HZ / hz;
    if divisor == 0 {
        // Faster than the crystal. The chip cannot, and pretending otherwise by
        // wrapping to 65536 would be the slowest possible tick.
        1
    } else if divisor > MAX_DIVISOR {
        MAX_DIVISOR
    } else {
        divisor
    }
}

/// The rate a divisor actually produces, which is rarely the one asked for.
#[must_use]
pub const fn hz_for(divisor: u32) -> u32 {
    if divisor == 0 {
        return BASE_HZ / MAX_DIVISOR;
    }
    BASE_HZ / divisor
}

/// The 8254, channel 0.
pub struct Pit<P: PortIo> {
    io: P,
}

impl<P: PortIo> Pit<P> {
    /// Wrap the port accessor. Nothing is programmed until [`Pit::start`].
    pub const fn new(io: P) -> Self {
        Self { io }
    }

    /// Start channel 0 as a rate generator at approximately `hz`, and return the
    /// rate it will actually run at.
    ///
    /// The counter starts as soon as both halves of the divisor have been
    /// written, so IRQ 0 begins arriving immediately — the caller must have the
    /// line masked, or a handler ready, before calling.
    pub fn start(&mut self, hz: u32) -> u32 {
        let divisor = divisor_for(hz);
        self.io.write(COMMAND, CMD_CHANNEL0_RATE_LOHI);
        // 65536 is written as 0: the counter is sixteen bits and the value that
        // means "the whole range" is the one that does not fit in it.
        let value = (divisor % MAX_DIVISOR) as u16;
        self.io.write(CHANNEL0_DATA, value as u8);
        self.io.write(CHANNEL0_DATA, (value >> 8) as u8);
        hz_for(divisor)
    }

    /// Stop the channel firing.
    ///
    /// Mode 0 with a counter of zero: the channel counts down once from 65536
    /// and then stops, rather than reloading. Masking IRQ 0 at the PIC is the
    /// other half and the one that matters — this only stops the chip pulling
    /// the line in the first place.
    pub fn stop(&mut self) {
        // Mode 0, one-shot, lobyte/hibyte.
        self.io.write(COMMAND, 0b0011_0000);
        self.io.write(CHANNEL0_DATA, 0);
        self.io.write(CHANNEL0_DATA, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        writes: Vec<(u16, u8)>,
    }

    // SAFETY: an in-memory model; nothing here touches hardware.
    unsafe impl PortIo for Recorder {
        fn write(&mut self, port: u16, value: u8) {
            self.writes.push((port, value));
        }
        fn read(&mut self, _port: u16) -> u8 {
            0
        }
        fn wait(&mut self) {}
    }

    #[test]
    fn the_divisor_is_the_crystal_over_the_rate() {
        assert_eq!(divisor_for(1000), 1193);
        assert_eq!(divisor_for(100), 11931);
        // 18.2 Hz is what a divisor of 65536 gives, and the slowest the chip can
        // be made to go.
        assert_eq!(divisor_for(18), MAX_DIVISOR);
        assert_eq!(divisor_for(1), MAX_DIVISOR);
    }

    #[test]
    fn a_rate_the_crystal_cannot_reach_clamps_instead_of_wrapping() {
        // Above the crystal, the honest divisor is 0, which the chip reads as
        // 65536 — the *slowest* possible tick. Asking for something too fast and
        // getting something fifty times too slow is the worst available answer.
        assert_eq!(divisor_for(BASE_HZ * 2), 1);
        assert_eq!(divisor_for(BASE_HZ), 1);
        // And zero is not a rate at all.
        assert_eq!(divisor_for(0), MAX_DIVISOR);
    }

    #[test]
    fn the_rate_reported_back_is_the_one_that_will_happen() {
        // Integer division means the requested rate is almost never the real
        // one, so `start` returns what the chip will do rather than what it was
        // asked for.
        assert_eq!(hz_for(divisor_for(1000)), 1000); // 1193182/1193 = 1000
        assert_eq!(hz_for(divisor_for(100)), 100);
        assert_eq!(hz_for(divisor_for(60)), 60);
        assert_eq!(hz_for(MAX_DIVISOR), 18);
    }

    #[test]
    fn programming_is_a_command_then_two_halves_of_the_divisor() {
        let mut pit = Pit::new(Recorder::default());
        let actual = pit.start(1000);
        assert_eq!(actual, 1000);
        assert_eq!(
            pit.io.writes,
            vec![
                (COMMAND, 0b0011_0100), // channel 0, lo/hi, mode 2, binary
                (CHANNEL0_DATA, 1193u16 as u8),
                (CHANNEL0_DATA, (1193u16 >> 8) as u8),
            ],
        );
    }

    #[test]
    fn the_largest_divisor_goes_out_as_zero() {
        // 65536 in a sixteen-bit counter. Writing 0xFF 0xFF instead would be one
        // tick short of a full cycle, forever.
        let mut pit = Pit::new(Recorder::default());
        pit.start(1);
        assert_eq!(pit.io.writes[1], (CHANNEL0_DATA, 0));
        assert_eq!(pit.io.writes[2], (CHANNEL0_DATA, 0));
    }

    #[test]
    fn the_command_selects_a_rate_generator_not_a_one_shot() {
        // Bits 3:1 are the mode. Mode 2 reloads and fires again; mode 0 fires
        // once and the tick stops after the first interrupt, which looks exactly
        // like an interrupt controller that dropped everything after the first.
        assert_eq!((CMD_CHANNEL0_RATE_LOHI >> 1) & 0b111, 2);
        assert_eq!(CMD_CHANNEL0_RATE_LOHI >> 6, 0, "not channel 0");
        assert_eq!((CMD_CHANNEL0_RATE_LOHI >> 4) & 0b11, 3, "not lobyte/hibyte access");
        assert_eq!(CMD_CHANNEL0_RATE_LOHI & 1, 0, "BCD counting, not binary");
    }
}
