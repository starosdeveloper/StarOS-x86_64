//! The High Precision Event Timer: a counter that knows its own frequency.
//!
//! Every other clock on this machine has to be measured before it can be
//! trusted. The 8254's crystal is a constant of the architecture but it counts
//! too slowly to time anything short; the local APIC's timer counts fast but at
//! the bus frequency, which varies by machine and by power state and is written
//! down nowhere; the TSC is fastest of all and, on older parts, changes rate when
//! the CPU does.
//!
//! The HPET is the exception. Its capability register states the period of one
//! tick in **femtoseconds**, so a reading converts to real time with no
//! calibration and no assumption. That makes it the ruler — not the clock the
//! kernel runs on, which will be the APIC timer, but the thing that ruler is cut
//! against.
//!
//! ## What is used and what is not
//! The main counter, and the enable bit. Nothing else. The HPET has up to
//! thirty-two comparators that can raise interrupts, and this kernel wants none
//! of them: the per-core timer belongs on the local APIC, where it is per-core.
//! Reading a monotonic counter is all that is asked, and it is asked twice —
//! once to calibrate, once to check the calibration.
//!
//! ## Sixty-four bits at a time
//! The counter is a single 64-bit register, read through [`Mmio64`]. Reading it
//! as two 32-bit halves is the classic way to get a timestamp that never existed:
//! the low half wraps between the two reads and the high half is taken from after
//! the carry, so the result jumps backwards by four billion ticks. A 32-bit HPET
//! (the capability bit says which) wraps its counter at 2^32 for real, which is
//! forty-three seconds at the 100 MHz QEMU provides — handled by measuring
//! *differences* with wrapping arithmetic rather than by pretending it does not
//! happen.

use crate::mmio::Mmio64;

/// General capabilities and id. Read-only.
pub const REG_CAPABILITIES: usize = 0x000;
/// General configuration. Bit 0 enables the counter.
pub const REG_CONFIG: usize = 0x010;
/// The main counter.
pub const REG_COUNTER: usize = 0x0F0;

/// Bit 0 of [`REG_CONFIG`]: run the main counter.
pub const CONFIG_ENABLE: u64 = 1 << 0;
/// Bit 1: route the first two comparators to the 8259's IRQ 0 and 8. Never set
/// here — those lines belong to the I/O APIC now.
pub const CONFIG_LEGACY_ROUTING: u64 = 1 << 1;

/// One femtosecond is 10^-15 s, so this many of them make a second.
pub const FEMTOSECONDS_PER_SECOND: u128 = 1_000_000_000_000_000;

/// The largest tick period the specification allows: 100 nanoseconds.
///
/// A period above this is not a slow HPET, it is a register that was not read
/// correctly — most often a capability register read as 32 bits, which puts the
/// period field in the wrong half.
pub const MAX_PERIOD_FS: u32 = 100_000_000;

/// What the capability register says about this HPET.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Period of one tick, in femtoseconds.
    pub period_fs: u32,
    /// How many comparators this block has.
    pub timers: u8,
    /// Whether the main counter is 64 bits wide rather than 32.
    pub counter_64bit: bool,
    /// The vendor id, for the boot log.
    pub vendor: u16,
    /// Hardware revision.
    pub revision: u8,
}

impl Capabilities {
    /// Decode the capability register.
    ///
    /// Returns `None` for a period of zero or one above the specification's
    /// maximum: both mean the register was not read as the 64-bit quantity it is,
    /// and a period of zero in particular would divide by zero downstream.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        let period_fs = (bits >> 32) as u32;
        if period_fs == 0 || period_fs > MAX_PERIOD_FS {
            return None;
        }
        Some(Self {
            period_fs,
            // The field is "number of timers minus one", so a block with one
            // comparator reports zero. Reading it as a count finds a timer that
            // does not exist.
            timers: (((bits >> 8) & 0x1F) as u8) + 1,
            counter_64bit: bits & (1 << 13) != 0,
            vendor: (bits >> 16) as u16,
            revision: bits as u8,
        })
    }

    /// Ticks per second.
    ///
    /// Computed rather than assumed: 10 MHz is what QEMU and most chipsets
    /// provide, and it is not architectural.
    #[must_use]
    pub const fn frequency_hz(self) -> u64 {
        (FEMTOSECONDS_PER_SECOND / self.period_fs as u128) as u64
    }

    /// Convert a tick count to nanoseconds.
    ///
    /// In 128-bit arithmetic: at 10 MHz a second is 10^7 ticks and the product
    /// with the period is 10^15, which fits — but the period can be as small as a
    /// femtosecond in principle and an hour is 10^13 ticks, which does not.
    /// Widening costs nothing on a path taken twice per boot.
    #[must_use]
    pub const fn ticks_to_ns(self, ticks: u64) -> u64 {
        let fs = ticks as u128 * self.period_fs as u128;
        (fs / 1_000_000) as u64
    }

    /// How many ticks span `ns` nanoseconds.
    #[must_use]
    pub const fn ns_to_ticks(self, ns: u64) -> u64 {
        let fs = ns as u128 * 1_000_000;
        (fs / self.period_fs as u128) as u64
    }
}

/// One HPET block.
pub struct Hpet<M: Mmio64> {
    regs: M,
    caps: Capabilities,
}

impl<M: Mmio64> Hpet<M> {
    /// Read the capabilities and wrap the block.
    ///
    /// Returns `None` if the capability register does not decode — see
    /// [`Capabilities::from_bits`]. The counter is not started here; that is
    /// [`Hpet::start`].
    pub fn new(mut regs: M) -> Option<Self> {
        let caps = Capabilities::from_bits(regs.read64(REG_CAPABILITIES))?;
        Some(Self { regs, caps })
    }

    /// What the capability register said.
    #[must_use]
    pub const fn capabilities(&self) -> Capabilities {
        self.caps
    }

    /// Start the main counter, and make sure legacy routing is off.
    ///
    /// Firmware often leaves legacy routing *on*, which wires the HPET's first
    /// two comparators to IRQ 0 and IRQ 8 in place of the 8254 and the RTC. That
    /// is a sensible thing for firmware to do and a bad thing to inherit: those
    /// lines are routed through the I/O APIC now, and a comparator firing on one
    /// of them would arrive as a timer interrupt this kernel never asked for.
    pub fn start(&mut self) {
        let config = self.regs.read64(REG_CONFIG);
        self.regs.write64(REG_CONFIG, (config & !CONFIG_LEGACY_ROUTING) | CONFIG_ENABLE);
    }

    /// Stop the main counter.
    pub fn stop(&mut self) {
        let config = self.regs.read64(REG_CONFIG);
        self.regs.write64(REG_CONFIG, config & !CONFIG_ENABLE);
    }

    /// Whether the counter is running.
    pub fn is_running(&mut self) -> bool {
        self.regs.read64(REG_CONFIG) & CONFIG_ENABLE != 0
    }

    /// The main counter.
    pub fn now(&mut self) -> u64 {
        self.regs.read64(REG_COUNTER)
    }

    /// Ticks elapsed between two readings, tolerating a 32-bit counter's wrap.
    ///
    /// Wrapping subtraction on the low 32 bits when the counter is that wide.
    /// A 32-bit HPET at 10 MHz wraps every seven minutes, which is longer than
    /// any measurement here and shorter than an uptime, so the case is real even
    /// though it will not be hit during a boot.
    #[must_use]
    pub const fn elapsed(&self, from: u64, to: u64) -> u64 {
        if self.caps.counter_64bit {
            to.wrapping_sub(from)
        } else {
            (to as u32).wrapping_sub(from as u32) as u64
        }
    }

    /// Nanoseconds between two readings.
    #[must_use]
    pub const fn elapsed_ns(&self, from: u64, to: u64) -> u64 {
        self.caps.ticks_to_ns(self.elapsed(from, to))
    }

    /// Spin until `ns` nanoseconds have passed.
    ///
    /// A busy wait, and the only kind available: there is no scheduler to yield
    /// to and the whole point of the exercise is to be the thing that measures
    /// time rather than something that waits for it.
    pub fn spin_ns(&mut self, ns: u64) {
        let target = self.caps.ns_to_ticks(ns);
        let start = self.now();
        loop {
            let now = self.now();
            if self.elapsed(start, now) >= target {
                return;
            }
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        writes: Vec<(usize, u64)>,
        state: std::collections::HashMap<usize, u64>,
    }

    // SAFETY: an in-memory model; nothing here touches hardware.
    unsafe impl Mmio64 for Recorder {
        fn read64(&mut self, offset: usize) -> u64 {
            self.state.get(&offset).copied().unwrap_or(0)
        }
        fn write64(&mut self, offset: usize, value: u64) {
            self.writes.push((offset, value));
            self.state.insert(offset, value);
        }
    }

    /// The capability register QEMU really presents: a 10 ns period — so 100 MHz,
    /// not the 10 MHz that gets quoted — three comparators, and a 64-bit counter.
    ///
    /// Taken from a live boot rather than from memory, because the first version
    /// of this constant was off by a factor of ten and every assertion below
    /// agreed with it perfectly. A self-consistent test of the wrong machine.
    const QEMU_CAPS: u64 = (10_000_000u64 << 32) | (1 << 13) | (2 << 8) | 0x01;

    fn hpet() -> Hpet<Recorder> {
        let mut regs = Recorder::default();
        regs.state.insert(REG_CAPABILITIES, QEMU_CAPS);
        Hpet::new(regs).unwrap()
    }

    #[test]
    fn the_period_is_in_the_upper_half_of_the_register() {
        // The single most likely mistake with this device: reading the capability
        // register as 32 bits puts the revision and timer count where the period
        // should be, and the frequency comes out in the exahertz.
        let caps = Capabilities::from_bits(QEMU_CAPS).unwrap();
        assert_eq!(caps.period_fs, 10_000_000);
        assert_eq!(caps.frequency_hz(), 100_000_000, "QEMU's HPET is 100 MHz");
        // A register read as 32 bits leaves the top half zero, hence period zero.
        assert_eq!(Capabilities::from_bits(QEMU_CAPS & 0xFFFF_FFFF), None);
    }

    #[test]
    fn an_impossible_period_is_refused_rather_than_divided_by() {
        // Zero would divide by zero in `frequency_hz`. Anything above 100 ns is
        // outside the specification and means the read was wrong.
        assert_eq!(Capabilities::from_bits(0), None);
        assert!(Capabilities::from_bits((MAX_PERIOD_FS as u64) << 32).is_some());
        assert_eq!(Capabilities::from_bits(((MAX_PERIOD_FS as u64) + 1) << 32), None);
    }

    #[test]
    fn the_timer_count_is_one_more_than_the_field() {
        // "Number of timers minus one". Reading it as a count finds a comparator
        // that is not there, and the last one is the one nothing else uses.
        let caps = Capabilities::from_bits(QEMU_CAPS).unwrap();
        assert_eq!(caps.timers, 3, "field holds 2");
        let one = Capabilities::from_bits((10_000_000u64 << 32) | (0 << 8)).unwrap();
        assert_eq!(one.timers, 1);
        let most = Capabilities::from_bits((10_000_000u64 << 32) | (31 << 8)).unwrap();
        assert_eq!(most.timers, 32);
    }

    #[test]
    fn ticks_and_nanoseconds_round_trip_at_the_real_frequency() {
        let caps = Capabilities::from_bits(QEMU_CAPS).unwrap();
        // 10 ns per tick: a hundred ticks are a microsecond.
        assert_eq!(caps.ticks_to_ns(100), 1_000);
        assert_eq!(caps.ns_to_ticks(1_000), 100);
        // A whole second, which is the interval the phase-2.3 criterion measures.
        assert_eq!(caps.ns_to_ticks(1_000_000_000), 100_000_000);
        assert_eq!(caps.ticks_to_ns(100_000_000), 1_000_000_000);
    }

    #[test]
    fn the_conversion_does_not_overflow_at_realistic_uptimes() {
        // A day at 100 MHz is 8.64e12 ticks; times the period that is 8.64e19,
        // which overflows u64 and does not overflow u128. The 128-bit widening in
        // `ticks_to_ns` is what this checks, and a 64-bit multiply would wrap to a
        // clock that runs backwards.
        let caps = Capabilities::from_bits(QEMU_CAPS).unwrap();
        let a_day = 86_400u64 * caps.frequency_hz();
        assert_eq!(caps.ticks_to_ns(a_day), 86_400_000_000_000);
        // And a fast HPET at an unrealistic uptime still does not wrap.
        let fast = Capabilities::from_bits(1u64 << 32).unwrap();
        assert_eq!(fast.frequency_hz(), 1_000_000_000_000_000);
        assert_eq!(fast.ticks_to_ns(u64::MAX / 2), u64::MAX / 2 / 1_000_000);
    }

    #[test]
    fn starting_enables_the_counter_and_clears_legacy_routing() {
        // Firmware leaves legacy routing on more often than not, which wires the
        // first two comparators to IRQ 0 and IRQ 8 - lines the I/O APIC now owns.
        let mut h = hpet();
        h.regs.state.insert(REG_CONFIG, CONFIG_LEGACY_ROUTING);
        h.start();
        assert_eq!(h.regs.writes, vec![(REG_CONFIG, CONFIG_ENABLE)]);
        assert!(h.is_running());
        h.regs.writes.clear();
        h.stop();
        assert_eq!(h.regs.writes, vec![(REG_CONFIG, 0)]);
        assert!(!h.is_running());
    }

    #[test]
    fn a_64_bit_counter_subtracts_across_the_whole_range() {
        let h = hpet();
        assert!(h.capabilities().counter_64bit);
        assert_eq!(h.elapsed(1000, 3000), 2000);
        // Backwards is a wrap, not a negative: the counter is monotonic and the
        // only way `to < from` is that it went all the way round.
        assert_eq!(h.elapsed(u64::MAX, 4), 5);
    }

    #[test]
    fn a_32_bit_counter_wraps_where_it_actually_wraps() {
        // A 32-bit counter wraps every 2^32 ticks, which at 100 MHz is 43
        // seconds. Subtracting these two readings in 64 bits gives a difference
        // of nearly 2^64 rather than 0x200 - an interval of six hundred years
        // where two microseconds passed.
        let mut regs = Recorder::default();
        regs.state.insert(REG_CAPABILITIES, QEMU_CAPS & !(1 << 13));
        let h = Hpet::new(regs).unwrap();
        assert!(!h.capabilities().counter_64bit);
        assert_eq!(h.elapsed(0xFFFF_FF00, 0x0000_0100), 0x200);
        // And the high half is ignored entirely, since the hardware never sets it.
        assert_eq!(h.elapsed(0xDEAD_0000_FFFF_FF00, 0x0000_0100), 0x200);
    }

    #[test]
    fn reading_the_counter_touches_only_the_counter() {
        let mut h = hpet();
        h.regs.state.insert(REG_COUNTER, 0x1234_5678_9ABC);
        assert_eq!(h.now(), 0x1234_5678_9ABC);
        assert!(h.regs.writes.is_empty(), "reading the clock changed it");
    }

    #[test]
    fn the_registers_are_where_the_specification_puts_them() {
        assert_eq!(REG_CAPABILITIES, 0x000);
        assert_eq!(REG_CONFIG, 0x010);
        assert_eq!(REG_COUNTER, 0x0F0);
        for reg in [REG_CAPABILITIES, REG_CONFIG, REG_COUNTER] {
            assert_eq!(reg % 8, 0, "{reg:#x} is not 8-byte aligned");
        }
    }
}
