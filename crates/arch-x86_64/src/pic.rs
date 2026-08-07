//! The two 8259 interrupt controllers, and why they are dealt with first.
//!
//! A PC has a pair of 8259s wired in cascade, and after a firmware hand-off they
//! are in whatever state the firmware left them: enabled, and delivering on
//! vectors **0 to 15**. Those vectors are not free. They are the CPU's own
//! exceptions — vector 8 is `#DF`, vector 13 is `#GP`, vector 14 is `#PF`. A
//! timer tick arriving on vector 8 is indistinguishable from a double fault, and
//! that is the failure this module exists to prevent: not a crash, but a fault
//! report that names the wrong thing entirely and sends the reader hunting for a
//! stack overflow that never happened.
//!
//! So before any interrupt may be enabled, the pair is re-initialised onto
//! vectors the architecture does not claim, and every line is masked. Only then
//! is `sti` survivable. The APICs in phase 2.2 replace the 8259s outright, and
//! they *still* have to be remapped first: a spurious PIC interrupt does not
//! stop happening because something better is now in charge.
//!
//! ## Why the port writes are behind a trait
//! The initialisation is four control words per chip in a fixed order, and every
//! one of them is a magic number whose meaning is positional. Nothing about a
//! wrong ICW3 is visible from outside — the chips accept it, and the symptom is
//! that interrupts from the slave never arrive, weeks later.
//! [`PortIo`](crate::port::PortIo) makes the sequence ordinary data, so the host
//! tests assert on *the exact writes*, in order, rather than on the constants
//! that go into them.

use crate::port::PortIo;

/// Command port of the master 8259.
pub const MASTER_COMMAND: u16 = 0x20;
/// Data port of the master: the mask register, and ICW2 through ICW4.
pub const MASTER_DATA: u16 = 0x21;
/// Command port of the slave.
pub const SLAVE_COMMAND: u16 = 0xA0;
/// Data port of the slave.
pub const SLAVE_DATA: u16 = 0xA1;

/// ICW1: begin initialisation, and promise an ICW4.
const ICW1_INIT: u8 = 0x11;
/// ICW3 for the master: a slave is attached to IRQ line 2, as a bit mask.
const ICW3_MASTER: u8 = 1 << CASCADE_IRQ;
/// ICW3 for the slave: the master line it hangs off, as a number.
const ICW3_SLAVE: u8 = CASCADE_IRQ;
/// ICW4: 8086/8088 mode. Without it the chips stay in MCS-80 mode and deliver
/// call addresses rather than vector numbers.
const ICW4_8086: u8 = 0x01;
/// OCW2: non-specific end of interrupt.
const OCW2_EOI: u8 = 0x20;
/// OCW3: the next read of the command port returns the In-Service Register.
const OCW3_READ_ISR: u8 = 0x0B;

/// The master line the slave is cascaded onto. Fixed by the wiring of every PC
/// ever built, not by configuration.
pub const CASCADE_IRQ: u8 = 2;

/// Number of IRQ lines across the pair.
pub const LINES: u8 = 16;

/// The line the master raises when it has an interrupt it cannot identify.
pub const SPURIOUS_MASTER: u8 = 7;
/// The same on the slave.
pub const SPURIOUS_SLAVE: u8 = 15;

/// The cascaded 8259 pair.
pub struct Pic8259<P: PortIo> {
    io: P,
    /// Vector the master's IRQ 0 is delivered on, or 0 before [`Pic8259::remap`].
    base: u8,
}

impl<P: PortIo> Pic8259<P> {
    /// Wrap the port accessor. Nothing is programmed until [`Pic8259::remap`].
    pub const fn new(io: P) -> Self {
        Self { io, base: 0 }
    }

    /// Vector the master's IRQ 0 is delivered on. Zero until remapped.
    #[must_use]
    pub const fn base(&self) -> u8 {
        self.base
    }

    /// Which vector `irq` will be delivered on.
    #[must_use]
    pub const fn vector_for(&self, irq: u8) -> u8 {
        self.base + irq
    }

    /// Which line delivered `vector`, if it was one of these chips'.
    #[must_use]
    pub const fn irq_for(&self, vector: u8) -> Option<u8> {
        if vector >= self.base && vector < self.base + LINES {
            Some(vector - self.base)
        } else {
            None
        }
    }

    /// Re-initialise both chips onto `base`..`base + 16`, with every line masked.
    ///
    /// The four control words go out in a fixed order and mean different things
    /// depending on position, which is the whole hazard: the chips accept any
    /// values, and a wrong ICW3 produces a pair that works perfectly for the
    /// master's eight lines and silently drops the slave's.
    ///
    /// Everything is masked on the way out rather than restoring what the
    /// firmware had. The firmware's mask reflected the firmware's drivers, none
    /// of which exist any more.
    ///
    /// # Panics
    /// If `base` is below 32, which would put a device interrupt back on a vector
    /// the architecture reserves for exceptions — the exact situation this
    /// function exists to end.
    pub fn remap(&mut self, base: u8) {
        assert!(base >= 32, "PIC base must clear the CPU's own exception vectors");
        assert!(base <= 255 - LINES, "PIC base leaves no room for 16 lines");
        self.base = base;

        // ICW1: both chips enter initialisation and expect three more words.
        self.io.write(MASTER_COMMAND, ICW1_INIT);
        self.io.wait();
        self.io.write(SLAVE_COMMAND, ICW1_INIT);
        self.io.wait();

        // ICW2: the vector each chip's line 0 maps to.
        self.io.write(MASTER_DATA, base);
        self.io.wait();
        self.io.write(SLAVE_DATA, base + 8);
        self.io.wait();

        // ICW3: how they are wired to each other. A bit mask on the master and a
        // plain number on the slave — the same fact, encoded two different ways,
        // which is why swapping them is such an easy mistake.
        self.io.write(MASTER_DATA, ICW3_MASTER);
        self.io.wait();
        self.io.write(SLAVE_DATA, ICW3_SLAVE);
        self.io.wait();

        // ICW4: deliver vector numbers, not 8080 call addresses.
        self.io.write(MASTER_DATA, ICW4_8086);
        self.io.wait();
        self.io.write(SLAVE_DATA, ICW4_8086);
        self.io.wait();

        self.set_masks(u16::MAX);
    }

    /// Set both mask registers at once. A set bit is a *masked* line.
    pub fn set_masks(&mut self, masks: u16) {
        self.io.write(MASTER_DATA, masks as u8);
        self.io.write(SLAVE_DATA, (masks >> 8) as u8);
    }

    /// Read both mask registers back.
    ///
    /// Worth having because it is the only part of the chips' state that *can* be
    /// read back: the ICWs are write-only, so "did the remap take" is a question
    /// only a delivered interrupt can answer.
    pub fn masks(&mut self) -> u16 {
        let low = u16::from(self.io.read(MASTER_DATA));
        let high = u16::from(self.io.read(SLAVE_DATA));
        low | (high << 8)
    }

    /// Allow `irq` to be delivered.
    ///
    /// Unmasking a slave line also unmasks the cascade line on the master, since
    /// every slave interrupt reaches the CPU through it. Leaving that to the
    /// caller is how a keyboard on IRQ 1 works and a real-time clock on IRQ 8
    /// mysteriously does not.
    pub fn unmask(&mut self, irq: u8) {
        let mut masks = self.masks();
        masks &= !(1u16 << irq);
        if irq >= 8 {
            masks &= !(1u16 << CASCADE_IRQ);
        }
        self.set_masks(masks);
    }

    /// Stop `irq` being delivered.
    pub fn mask(&mut self, irq: u8) {
        let masks = self.masks() | (1u16 << irq);
        self.set_masks(masks);
    }

    /// Mask every line. The chips stay remapped, which is the point: a masked
    /// 8259 still emits the occasional spurious interrupt, and it must land
    /// somewhere harmless.
    pub fn mask_all(&mut self) {
        self.set_masks(u16::MAX);
    }

    /// Acknowledge `irq`.
    ///
    /// A slave interrupt needs two acknowledgements, slave first: the master's
    /// in-service bit for the cascade line stays set until it gets its own, and
    /// while it is set nothing of equal or lower priority is delivered — which
    /// looks like the interrupt controller dying rather than like a missing
    /// write.
    pub fn end_of_interrupt(&mut self, irq: u8) {
        if irq >= 8 {
            self.io.write(SLAVE_COMMAND, OCW2_EOI);
        }
        self.io.write(MASTER_COMMAND, OCW2_EOI);
    }

    /// Whether an interrupt on `irq` is spurious: the chip raised the line but
    /// has nothing in service behind it.
    ///
    /// Only lines 7 and 15 can be spurious — they are the lowest priority on each
    /// chip, and what the 8259 falls back to when a line drops between the
    /// request and the acknowledge. A spurious interrupt must **not** be
    /// acknowledged on the chip that raised it, because there is nothing in
    /// service to acknowledge; a spurious 15 still needs the master's EOI,
    /// because the master really did see the cascade line go high.
    pub fn is_spurious(&mut self, irq: u8) -> bool {
        let command = match irq {
            SPURIOUS_MASTER => MASTER_COMMAND,
            SPURIOUS_SLAVE => SLAVE_COMMAND,
            _ => return false,
        };
        self.io.write(command, OCW3_READ_ISR);
        self.io.read(command) & (1 << 7) == 0
    }

    /// Acknowledge a spurious interrupt correctly: nothing for line 7, and the
    /// master only for line 15.
    pub fn end_of_spurious(&mut self, irq: u8) {
        if irq == SPURIOUS_SLAVE {
            self.io.write(MASTER_COMMAND, OCW2_EOI);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A model of the four 8259 registers that records everything done to them.
    ///
    /// The two kinds of port behave differently and the difference matters here.
    /// A *data* port is an ordinary read/write register — it holds the mask, and
    /// reading it back returns what was written. A *command* port is not: writing
    /// it issues a control word, and reading it returns whichever internal
    /// register the last OCW3 selected. Modelling both as one map would make the
    /// spurious-interrupt tests pass by accident, because the OCW3 that selects
    /// the ISR would also be the value the ISR read returns.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<(u16, u8)>,
        /// The mask registers, which really do read back.
        data: std::collections::HashMap<u16, u8>,
        /// What a command port returns when read: the ISR, in these tests.
        status: std::collections::HashMap<u16, u8>,
        waits: usize,
    }

    // SAFETY: an in-memory model; nothing here touches hardware.
    unsafe impl PortIo for Recorder {
        fn write(&mut self, port: u16, value: u8) {
            self.writes.push((port, value));
            if port == MASTER_DATA || port == SLAVE_DATA {
                self.data.insert(port, value);
            }
        }
        fn read(&mut self, port: u16) -> u8 {
            if port == MASTER_DATA || port == SLAVE_DATA {
                self.data.get(&port).copied().unwrap_or(0)
            } else {
                self.status.get(&port).copied().unwrap_or(0)
            }
        }
        fn wait(&mut self) {
            self.waits += 1;
        }
    }

    fn remapped() -> Pic8259<Recorder> {
        let mut pic = Pic8259::new(Recorder::default());
        pic.remap(32);
        pic.io.writes.clear();
        pic
    }

    #[test]
    fn the_initialisation_sequence_is_exactly_this() {
        // Asserted as a whole sequence rather than word by word: the words mean
        // different things depending on where they fall, so an order that is
        // right in every individual assertion can still be wrong.
        let mut pic = Pic8259::new(Recorder::default());
        pic.remap(32);
        assert_eq!(
            pic.io.writes,
            vec![
                (MASTER_COMMAND, 0x11), // ICW1: init, ICW4 to follow
                (SLAVE_COMMAND, 0x11),
                (MASTER_DATA, 32),      // ICW2: vector base
                (SLAVE_DATA, 40),
                (MASTER_DATA, 0b100),   // ICW3: slave on line 2, as a bit mask
                (SLAVE_DATA, 2),        // ICW3: cascade line, as a number
                (MASTER_DATA, 0x01),    // ICW4: 8086 mode
                (SLAVE_DATA, 0x01),
                (MASTER_DATA, 0xFF),    // every line masked
                (SLAVE_DATA, 0xFF),
            ],
        );
    }

    #[test]
    fn the_two_icw3_encodings_are_not_interchangeable() {
        // The master is told *which line* the slave is on as a mask; the slave is
        // told the same line as an integer. Swapping them yields 2 and 4, both of
        // which the chips accept and neither of which is right.
        assert_eq!(ICW3_MASTER, 0b0000_0100);
        assert_eq!(ICW3_SLAVE, 2);
        assert_ne!(u32::from(ICW3_MASTER), u32::from(ICW3_SLAVE));
    }

    #[test]
    fn the_chips_are_given_settling_time_between_control_words() {
        // Eight control words, eight waits. Not decoration: without them, fast
        // machines drop words on real chipsets, and the failure is intermittent.
        let mut pic = Pic8259::new(Recorder::default());
        pic.remap(32);
        assert_eq!(pic.io.waits, 8);
    }

    #[test]
    fn a_base_that_collides_with_the_exception_vectors_is_refused() {
        // The whole point of remapping. Vector 8 is #DF; a timer tick arriving
        // there reports a double fault that never happened.
        for base in [0u8, 8, 14, 31] {
            let mut pic = Pic8259::new(Recorder::default());
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pic.remap(base))).is_err(),
                    "base {base} was accepted");
        }
    }

    #[test]
    fn a_base_with_no_room_for_sixteen_lines_is_refused() {
        let mut pic = Pic8259::new(Recorder::default());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pic.remap(250))).is_err());
    }

    #[test]
    fn vectors_and_lines_are_the_same_fact_read_two_ways() {
        let pic = remapped();
        assert_eq!(pic.vector_for(0), 32);
        assert_eq!(pic.vector_for(1), 33); // the keyboard
        assert_eq!(pic.vector_for(15), 47);
        assert_eq!(pic.irq_for(32), Some(0));
        assert_eq!(pic.irq_for(47), Some(15));
        // The boundaries either side: a CPU exception and the first vector past
        // the pair, which will belong to the APIC.
        assert_eq!(pic.irq_for(31), None);
        assert_eq!(pic.irq_for(48), None);
        for irq in 0..LINES {
            assert_eq!(pic.irq_for(pic.vector_for(irq)), Some(irq));
        }
    }

    #[test]
    fn masks_split_across_the_two_chips_in_the_right_order() {
        let mut pic = remapped();
        pic.set_masks(0xFE_DC);
        assert_eq!(pic.io.writes, vec![(MASTER_DATA, 0xDC), (SLAVE_DATA, 0xFE)]);
        // And read back as one word: low byte master, high byte slave.
        assert_eq!(pic.masks(), 0xFE_DC);
    }

    #[test]
    fn unmasking_one_line_leaves_the_others_alone() {
        let mut pic = remapped();
        assert_eq!(pic.masks(), 0xFFFF);
        pic.unmask(1);
        assert_eq!(pic.masks(), 0xFFFD, "the keyboard alone should be open");
        pic.unmask(0);
        assert_eq!(pic.masks(), 0xFFFC);
        pic.mask(1);
        assert_eq!(pic.masks(), 0xFFFE);
    }

    #[test]
    fn unmasking_a_slave_line_opens_the_cascade_too() {
        // Every slave interrupt reaches the CPU through the master's line 2.
        // Forgetting it is the bug where the keyboard works and the RTC does not.
        let mut pic = remapped();
        pic.unmask(8);
        let masks = pic.masks();
        assert_eq!(masks & (1 << 8), 0, "line 8 is still masked");
        assert_eq!(masks & (1 << CASCADE_IRQ), 0, "the cascade line was left masked");
        // ...and a master line does not open it gratuitously.
        let mut pic = remapped();
        pic.unmask(1);
        assert_ne!(pic.masks() & (1 << CASCADE_IRQ), 0);
    }

    #[test]
    fn a_slave_interrupt_is_acknowledged_twice_slave_first() {
        let mut pic = remapped();
        pic.end_of_interrupt(1);
        assert_eq!(pic.io.writes, vec![(MASTER_COMMAND, OCW2_EOI)]);

        let mut pic = remapped();
        pic.end_of_interrupt(9);
        // Order matters: the master's cascade bit stays in service until it gets
        // its own EOI, and while it does, nothing of equal or lower priority is
        // delivered at all.
        assert_eq!(
            pic.io.writes,
            vec![(SLAVE_COMMAND, OCW2_EOI), (MASTER_COMMAND, OCW2_EOI)],
        );
    }

    #[test]
    fn only_the_lowest_priority_line_on_each_chip_can_be_spurious() {
        let mut pic = remapped();
        for irq in 0..LINES {
            let expected = irq == SPURIOUS_MASTER || irq == SPURIOUS_SLAVE;
            // The recorder returns 0 for the ISR, i.e. nothing in service, so
            // every line that *can* be spurious reads as spurious here.
            assert_eq!(pic.is_spurious(irq), expected, "irq {irq}");
        }
    }

    #[test]
    fn a_line_with_something_in_service_is_not_spurious() {
        let mut pic = remapped();
        // ISR bit 7 set: the chip really does have line 7 in service.
        pic.io.status.insert(MASTER_COMMAND, 0x80);
        assert!(!pic.is_spurious(SPURIOUS_MASTER));
        // Reading the ISR takes an OCW3 first; without it the command port
        // returns the IRR and the answer is about the wrong register.
        assert_eq!(pic.io.writes, vec![(MASTER_COMMAND, OCW3_READ_ISR)]);
    }

    #[test]
    fn a_spurious_interrupt_is_not_acknowledged_on_the_chip_that_raised_it() {
        // Nothing is in service, so an EOI would clear a bit belonging to a real
        // interrupt that happens to be pending underneath.
        let mut pic = remapped();
        pic.end_of_spurious(SPURIOUS_MASTER);
        assert!(pic.io.writes.is_empty(), "acknowledged a spurious master interrupt");

        // The slave's line 15 is different: the master genuinely saw the cascade
        // line go high, so the master, and only the master, is acknowledged.
        let mut pic = remapped();
        pic.end_of_spurious(SPURIOUS_SLAVE);
        assert_eq!(pic.io.writes, vec![(MASTER_COMMAND, OCW2_EOI)]);
    }
}
