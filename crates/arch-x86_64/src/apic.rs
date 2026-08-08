//! The local APIC and the I/O APIC — the interrupt controller that replaces the
//! 8259s.
//!
//! Two chips with two very different jobs, and conflating them is the usual
//! mistake. The **local** APIC is part of the CPU: one per core, always at the
//! same physical address on every core, and what it does is *receive* — it holds
//! the priority logic, the end-of-interrupt register, the per-core timer, and the
//! doorbell other cores ring to send an IPI. The **I/O** APIC is on the
//! motherboard: one (or more) for the whole machine, and what it does is *route*
//! — it takes a device's interrupt line and decides which vector on which core it
//! becomes.
//!
//! ## What the aarch64 tree does not have to think about
//! A GIC hands the CPU an interrupt id and the handler reads `GICC_IAR` to find
//! out which. Here the routing is decided *in advance*: the I/O APIC is
//! programmed with "line 2 becomes vector 32 on APIC id 0", and when the vector
//! arrives the CPU already knows which handler to run because the vector *is* the
//! identification. There is nothing to ask the controller afterwards. That is
//! why [`staros_hal::AcknowledgingController`] exists as a separate trait and why
//! nothing here implements it.
//!
//! ## Global system interrupts are not IRQ numbers
//! The I/O APIC has one redirection entry per *global system interrupt*, and the
//! legacy IRQ numbers software grew up with map onto GSIs by a table the firmware
//! publishes — not by identity. On nearly every PC the PIT's IRQ 0 arrives as
//! GSI 2, because the 8259 cascade line got there first. Programming entry 0 for
//! the timer therefore configures a line nothing is attached to, and the symptom
//! is silence. The mapping is read from the MADT (`staros_acpi::Madt::gsi_for_irq`)
//! and never assumed.

use crate::mmio::Mmio32;

// --------------------------------------------------------------------------
// Local APIC
// --------------------------------------------------------------------------

/// Local APIC register offsets. Every one is 16-byte spaced, which is why the
/// numbers look sparse: the architecture reserves the three words after each.
pub mod lapic_reg {
    /// This core's APIC id, in bits 24..31.
    pub const ID: usize = 0x020;
    /// Version, and the number of LVT entries minus one in bits 16..23.
    pub const VERSION: usize = 0x030;
    /// Task priority. Zero means "accept everything"; firmware sometimes leaves
    /// it high, which silently blocks every interrupt below that priority.
    pub const TASK_PRIORITY: usize = 0x080;
    /// End of interrupt. Write zero — any other value is architecturally
    /// undefined, unlike the GIC's EOIR which takes the id.
    pub const EOI: usize = 0x0B0;
    /// Spurious interrupt vector, and the software enable bit.
    pub const SPURIOUS: usize = 0x0F0;
    /// Interrupt command, low half: vector and delivery mode. Writing this is
    /// what sends the IPI.
    pub const ICR_LOW: usize = 0x300;
    /// Interrupt command, high half: the destination APIC id.
    pub const ICR_HIGH: usize = 0x310;
    /// Local vector table: timer.
    pub const LVT_TIMER: usize = 0x320;
    /// Local vector table: `LINT0`.
    pub const LVT_LINT0: usize = 0x350;
    /// Local vector table: `LINT1`.
    pub const LVT_LINT1: usize = 0x360;
    /// Local vector table: internal error.
    pub const LVT_ERROR: usize = 0x370;
}

/// Bit 8 of [`lapic_reg::SPURIOUS`]: the software enable.
///
/// Distinct from the hardware enable in `IA32_APIC_BASE`, and both are needed.
/// The MSR bit says the APIC exists at all; this one says it may deliver.
pub const SPURIOUS_ENABLE: u32 = 1 << 8;

/// Bit 16 of an LVT entry: masked.
pub const LVT_MASKED: u32 = 1 << 16;

/// The MSR that holds the local APIC's base address and its hardware enable.
pub const IA32_APIC_BASE: u32 = 0x1B;
/// Bit 11 of [`IA32_APIC_BASE`]: the APIC is enabled.
pub const APIC_BASE_ENABLE: u64 = 1 << 11;
/// Bit 8: this core is the bootstrap processor. Read-only, and worth reporting.
pub const APIC_BASE_BSP: u64 = 1 << 8;

/// One core's local APIC.
pub struct LocalApic<M: Mmio32> {
    regs: M,
}

impl<M: Mmio32> LocalApic<M> {
    /// Wrap the registers. Nothing is programmed until [`LocalApic::enable`].
    pub const fn new(regs: M) -> Self {
        Self { regs }
    }

    /// This core's APIC id — the value an IPI is addressed to, and what the I/O
    /// APIC's redirection entries name as a destination.
    pub fn id(&mut self) -> u8 {
        (self.regs.read(lapic_reg::ID) >> 24) as u8
    }

    /// The version register's low byte. `0x14` and up means an integrated APIC;
    /// below `0x10` is the discrete 82489DX, which no machine this kernel will
    /// see still has.
    pub fn version(&mut self) -> u8 {
        self.regs.read(lapic_reg::VERSION) as u8
    }

    /// How many local vector table entries this APIC has.
    pub fn lvt_entries(&mut self) -> u8 {
        ((self.regs.read(lapic_reg::VERSION) >> 16) as u8).saturating_add(1)
    }

    /// Software-enable the APIC and give it a spurious vector.
    ///
    /// Three things, and leaving out any one of them produces a controller that
    /// looks configured and delivers nothing:
    ///
    /// * the **task priority** goes to zero. Firmware sometimes leaves it raised,
    ///   and a raised TPR blocks every vector below it — silently, since a
    ///   blocked interrupt is not an error, just an absence.
    /// * the three local vector table entries this kernel does not use are
    ///   **masked**. Firmware may have pointed them at vectors that meant
    ///   something under its own IDT and mean something else under this one.
    /// * the spurious vector register gets a vector *and* the enable bit. The
    ///   vector matters: the APIC raises it when an interrupt is withdrawn
    ///   between the request and the acknowledge, and it must land somewhere the
    ///   kernel recognises rather than on whatever the register happened to hold.
    pub fn enable(&mut self, spurious_vector: u8) {
        self.regs.write(lapic_reg::TASK_PRIORITY, 0);
        for lvt in [lapic_reg::LVT_TIMER, lapic_reg::LVT_LINT0, lapic_reg::LVT_LINT1] {
            self.regs.write(lvt, LVT_MASKED);
        }
        // The error LVT is left masked too, but with a real vector behind the
        // mask so phase 2.3 can unmask it without re-deriving one.
        self.regs.write(lapic_reg::LVT_ERROR, LVT_MASKED | u32::from(spurious_vector));
        self.regs
            .write(lapic_reg::SPURIOUS, SPURIOUS_ENABLE | u32::from(spurious_vector));
    }

    /// Whether the software enable bit is set, read back from the register.
    pub fn is_enabled(&mut self) -> bool {
        self.regs.read(lapic_reg::SPURIOUS) & SPURIOUS_ENABLE != 0
    }

    /// The vector the APIC raises for a spurious interrupt.
    pub fn spurious_vector(&mut self) -> u8 {
        self.regs.read(lapic_reg::SPURIOUS) as u8
    }

    /// Acknowledge the interrupt being handled.
    ///
    /// Takes no argument, and that is the difference from the GIC that the HAL
    /// had to be reshaped around: the local APIC has one in-service register and
    /// an EOI always clears its highest-priority bit. There is nothing to name.
    pub fn end_of_interrupt(&mut self) {
        self.regs.write(lapic_reg::EOI, 0);
    }
}

// --------------------------------------------------------------------------
// I/O APIC
// --------------------------------------------------------------------------

/// Offset of the register-select window. Write the index of the register you
/// want here.
pub const IOAPIC_SELECT: usize = 0x00;
/// Offset of the data window. Reads and writes here hit whichever register
/// [`IOAPIC_SELECT`] last named.
pub const IOAPIC_WINDOW: usize = 0x10;

/// Indirect register: this controller's id.
pub const IOAPIC_REG_ID: u32 = 0x00;
/// Indirect register: version, and the highest entry index in bits 16..23.
pub const IOAPIC_REG_VERSION: u32 = 0x01;
/// Indirect register: the first redirection entry. Each entry is two registers.
pub const IOAPIC_REG_REDIRECT: u32 = 0x10;

/// How a redirection entry delivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirection {
    /// The vector the CPU will see.
    pub vector: u8,
    /// APIC id of the core to deliver to.
    pub destination: u8,
    /// Active low rather than active high. From the MADT's override flags —
    /// the ISA bus is active high and PCI is active low, and getting it wrong
    /// gives either a storm or nothing at all.
    pub active_low: bool,
    /// Level triggered rather than edge triggered. Same source, same stakes.
    pub level_triggered: bool,
    /// Whether the line is masked.
    pub masked: bool,
}

impl Redirection {
    /// A masked entry, so an unprogrammed line cannot deliver.
    #[must_use]
    pub const fn masked() -> Self {
        Self {
            vector: 0,
            destination: 0,
            active_low: false,
            level_triggered: false,
            masked: true,
        }
    }

    /// The low half of the entry: everything except the destination.
    ///
    /// Delivery mode is left at zero, "fixed" — deliver this exact vector to
    /// this exact core, rather than letting the hardware pick the lowest-priority
    /// one. Bring-up wants the answer to be predictable more than it wants it to
    /// be balanced.
    #[must_use]
    pub const fn low_bits(self) -> u32 {
        let mut bits = self.vector as u32;
        if self.active_low {
            bits |= 1 << 13;
        }
        if self.level_triggered {
            bits |= 1 << 15;
        }
        if self.masked {
            bits |= 1 << 16;
        }
        bits
    }

    /// The high half: the destination APIC id, in the *top* byte.
    #[must_use]
    pub const fn high_bits(self) -> u32 {
        (self.destination as u32) << 24
    }

    /// Decode an entry from the two halves.
    #[must_use]
    pub const fn from_bits(low: u32, high: u32) -> Self {
        Self {
            vector: low as u8,
            destination: (high >> 24) as u8,
            active_low: low & (1 << 13) != 0,
            level_triggered: low & (1 << 15) != 0,
            masked: low & (1 << 16) != 0,
        }
    }
}

/// Polarity and trigger mode, decoded from the MADT's override flags.
///
/// Two bits each, and the value `0` means "whatever the bus normally does" —
/// which for the ISA bus is active high and edge triggered. Firmware emits
/// `0` far more often than it emits the explicit encodings, so the default is
/// the case that has to be right.
#[must_use]
pub const fn polarity_and_trigger(flags: u16) -> (bool, bool) {
    let active_low = matches!(flags & 0b11, 0b11);
    let level = matches!((flags >> 2) & 0b11, 0b11);
    (active_low, level)
}

/// One I/O APIC.
pub struct IoApic<M: Mmio32> {
    regs: M,
    /// The first global system interrupt this controller covers.
    gsi_base: u32,
}

impl<M: Mmio32> IoApic<M> {
    /// Wrap the registers of a controller whose first GSI is `gsi_base`.
    pub const fn new(regs: M, gsi_base: u32) -> Self {
        Self { regs, gsi_base }
    }

    /// The first GSI this controller covers.
    #[must_use]
    pub const fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    /// Read one indirect register.
    fn read_reg(&mut self, index: u32) -> u32 {
        self.regs.write(IOAPIC_SELECT, index);
        self.regs.read(IOAPIC_WINDOW)
    }

    /// Write one indirect register.
    fn write_reg(&mut self, index: u32, value: u32) {
        self.regs.write(IOAPIC_SELECT, index);
        self.regs.write(IOAPIC_WINDOW, value);
    }

    /// This controller's id, from bits 24..27 of the id register.
    pub fn id(&mut self) -> u8 {
        ((self.read_reg(IOAPIC_REG_ID) >> 24) & 0xF) as u8
    }

    /// The version register's low byte.
    pub fn version(&mut self) -> u8 {
        self.read_reg(IOAPIC_REG_VERSION) as u8
    }

    /// How many redirection entries this controller has.
    ///
    /// The register holds the highest *index*, so the count is one more. Reading
    /// it rather than assuming 24 matters: a machine can have several I/O APICs
    /// with different sizes, and writing past the last entry lands in whatever
    /// the chip decodes next.
    pub fn entry_count(&mut self) -> u32 {
        ((self.read_reg(IOAPIC_REG_VERSION) >> 16) & 0xFF) + 1
    }

    /// Whether `gsi` belongs to this controller.
    pub fn covers(&mut self, gsi: u32) -> bool {
        let count = self.entry_count();
        gsi >= self.gsi_base && gsi < self.gsi_base + count
    }

    /// The two indirect register indices for `gsi`'s redirection entry.
    fn entry_regs(&self, gsi: u32) -> (u32, u32) {
        let index = gsi - self.gsi_base;
        let low = IOAPIC_REG_REDIRECT + index * 2;
        (low, low + 1)
    }

    /// Program `gsi`'s redirection entry.
    ///
    /// The high half goes first. The low half holds the mask bit, so writing it
    /// last means the entry is never briefly live with the previous
    /// destination — which, on a line that is already asserting, is one
    /// interrupt delivered to the wrong core.
    ///
    /// # Panics
    /// If `gsi` is not one this controller covers.
    pub fn set_redirection(&mut self, gsi: u32, entry: Redirection) {
        assert!(self.covers(gsi), "GSI {gsi} does not belong to this I/O APIC");
        let (low, high) = self.entry_regs(gsi);
        self.write_reg(high, entry.high_bits());
        self.write_reg(low, entry.low_bits());
    }

    /// Read `gsi`'s redirection entry back.
    ///
    /// # Panics
    /// If `gsi` is not one this controller covers.
    pub fn redirection(&mut self, gsi: u32) -> Redirection {
        assert!(self.covers(gsi), "GSI {gsi} does not belong to this I/O APIC");
        let (low, high) = self.entry_regs(gsi);
        let low = self.read_reg(low);
        let high = self.read_reg(high);
        Redirection::from_bits(low, high)
    }

    /// Mask or unmask `gsi` without disturbing the rest of its entry.
    ///
    /// # Panics
    /// If `gsi` is not one this controller covers.
    pub fn set_masked(&mut self, gsi: u32, masked: bool) {
        let mut entry = self.redirection(gsi);
        entry.masked = masked;
        let (low, _) = self.entry_regs(gsi);
        self.write_reg(low, entry.low_bits());
    }

    /// Mask every entry.
    ///
    /// What firmware leaves behind is not knowable, and an entry pointing at a
    /// vector that meant something under the firmware's IDT means something else
    /// under this one.
    pub fn mask_all(&mut self) {
        let count = self.entry_count();
        for index in 0..count {
            let gsi = self.gsi_base + index;
            let (low, high) = self.entry_regs(gsi);
            self.write_reg(high, 0);
            self.write_reg(low, Redirection::masked().low_bits());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A model of a register window that records every access in order.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<(usize, u32)>,
        /// Register contents, for the ones a test wants to read back.
        state: std::collections::HashMap<usize, u32>,
    }

    // SAFETY: an in-memory model; nothing here touches hardware.
    unsafe impl Mmio32 for Recorder {
        fn read(&mut self, offset: usize) -> u32 {
            self.state.get(&offset).copied().unwrap_or(0)
        }
        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
            self.state.insert(offset, value);
        }
    }

    /// A model of an I/O APIC's indirect register file: a select register and a
    /// window that reads and writes whichever register was last selected.
    ///
    /// Modelling the indirection rather than flattening it is the point. A driver
    /// that wrote the index and the value to the same port, or read the window
    /// without selecting first, would work perfectly against a flat model and
    /// route nothing on a real chip.
    #[derive(Default)]
    struct IndirectRecorder {
        selected: u32,
        regs: std::collections::HashMap<u32, u32>,
        /// Every access as it happened: `(register index, value, is_write)`.
        log: Vec<(u32, u32, bool)>,
    }

    // SAFETY: an in-memory model of the two-register window.
    unsafe impl Mmio32 for IndirectRecorder {
        fn read(&mut self, offset: usize) -> u32 {
            assert_eq!(offset, IOAPIC_WINDOW, "read from something other than the window");
            let value = self.regs.get(&self.selected).copied().unwrap_or(0);
            self.log.push((self.selected, value, false));
            value
        }
        fn write(&mut self, offset: usize, value: u32) {
            match offset {
                IOAPIC_SELECT => self.selected = value,
                IOAPIC_WINDOW => {
                    self.regs.insert(self.selected, value);
                    self.log.push((self.selected, value, true));
                }
                other => panic!("write to offset {other:#x}, which is not a register"),
            }
        }
    }

    fn io_apic(entries: u32, gsi_base: u32) -> IoApic<IndirectRecorder> {
        let mut regs = IndirectRecorder::default();
        regs.regs.insert(IOAPIC_REG_VERSION, ((entries - 1) << 16) | 0x11);
        IoApic::new(regs, gsi_base)
    }

    #[test]
    fn local_apic_registers_are_where_the_architecture_puts_them() {
        // Every one is 16-byte spaced. A transposed digit lands on a reserved
        // word, which reads as zero and accepts writes, so nothing complains.
        assert_eq!(lapic_reg::ID, 0x20);
        assert_eq!(lapic_reg::VERSION, 0x30);
        assert_eq!(lapic_reg::TASK_PRIORITY, 0x80);
        assert_eq!(lapic_reg::EOI, 0xB0);
        assert_eq!(lapic_reg::SPURIOUS, 0xF0);
        assert_eq!(lapic_reg::ICR_LOW, 0x300);
        assert_eq!(lapic_reg::ICR_HIGH, 0x310);
        for reg in [
            lapic_reg::ID,
            lapic_reg::VERSION,
            lapic_reg::TASK_PRIORITY,
            lapic_reg::EOI,
            lapic_reg::SPURIOUS,
            lapic_reg::ICR_LOW,
            lapic_reg::ICR_HIGH,
            lapic_reg::LVT_TIMER,
            lapic_reg::LVT_LINT0,
            lapic_reg::LVT_LINT1,
            lapic_reg::LVT_ERROR,
        ] {
            assert_eq!(reg % 16, 0, "{reg:#x} is not on a 16-byte boundary");
        }
    }

    #[test]
    fn enabling_lowers_the_priority_and_masks_what_firmware_left() {
        let mut lapic = LocalApic::new(Recorder::default());
        lapic.enable(0xFF);
        assert_eq!(
            lapic.regs.writes,
            vec![
                // Zero first: a raised task priority blocks every vector below it,
                // and firmware does leave it raised.
                (lapic_reg::TASK_PRIORITY, 0),
                (lapic_reg::LVT_TIMER, LVT_MASKED),
                (lapic_reg::LVT_LINT0, LVT_MASKED),
                (lapic_reg::LVT_LINT1, LVT_MASKED),
                (lapic_reg::LVT_ERROR, LVT_MASKED | 0xFF),
                // The enable bit and the vector together, last.
                (lapic_reg::SPURIOUS, SPURIOUS_ENABLE | 0xFF),
            ],
        );
        assert!(lapic.is_enabled());
        assert_eq!(lapic.spurious_vector(), 0xFF);
    }

    #[test]
    fn end_of_interrupt_writes_zero_and_names_nothing() {
        // The difference from the GIC in one assertion. `GICC_EOIR` takes the
        // interrupt id; this register takes zero and clears the highest-priority
        // in-service bit by itself.
        let mut lapic = LocalApic::new(Recorder::default());
        lapic.end_of_interrupt();
        assert_eq!(lapic.regs.writes, vec![(lapic_reg::EOI, 0)]);
    }

    #[test]
    fn the_apic_id_is_the_top_byte() {
        let mut lapic = LocalApic::new(Recorder::default());
        lapic.regs.state.insert(lapic_reg::ID, 0x0F00_0000);
        assert_eq!(lapic.id(), 0x0F);
        // Version register: low byte is the version, bits 16..23 are the highest
        // LVT index, so the count is one more.
        lapic.regs.state.insert(lapic_reg::VERSION, 0x0006_0014);
        assert_eq!(lapic.version(), 0x14);
        assert_eq!(lapic.lvt_entries(), 7);
    }

    #[test]
    fn an_indirect_register_is_selected_before_it_is_touched() {
        // The whole hazard of this chip. A driver that skipped the select would
        // read and write whatever was selected last, which is usually the
        // register it looked at previously.
        let mut io = io_apic(24, 0);
        let count = io.entry_count();
        assert_eq!(count, 24);
        assert_eq!(io.regs.log, vec![(IOAPIC_REG_VERSION, 0x0017_0011, false)]);
    }

    #[test]
    fn a_redirection_entry_is_two_registers_at_the_right_indices() {
        let mut io = io_apic(24, 0);
        io.regs.log.clear();
        io.set_redirection(2, Redirection {
            vector: 32,
            destination: 0,
            active_low: false,
            level_triggered: false,
            masked: false,
        });
        // Entry n lives at 0x10 + 2n and 0x11 + 2n. GSI 2 is therefore 0x14/0x15,
        // and an off-by-one here programs the neighbouring line.
        let writes: Vec<_> = io.regs.log.iter().filter(|e| e.2).map(|e| (e.0, e.1)).collect();
        assert_eq!(writes, vec![(0x15, 0), (0x14, 32)]);
    }

    #[test]
    fn the_high_half_is_written_before_the_mask_is_lifted() {
        // The low half holds the mask bit. Writing it first would leave the entry
        // briefly live with whatever destination was there before, and on a line
        // that is already asserting that is one interrupt delivered to the wrong
        // core.
        let mut io = io_apic(24, 0);
        io.regs.log.clear();
        io.set_redirection(1, Redirection {
            vector: 33,
            destination: 3,
            active_low: false,
            level_triggered: false,
            masked: false,
        });
        let writes: Vec<_> = io.regs.log.iter().filter(|e| e.2).collect();
        assert_eq!(writes[0].0, 0x13, "the high half must go out first");
        assert_eq!(writes[1].0, 0x12);
    }

    #[test]
    fn a_redirection_round_trips_through_its_two_halves() {
        let entry = Redirection {
            vector: 0x35,
            destination: 0x07,
            active_low: true,
            level_triggered: true,
            masked: false,
        };
        assert_eq!(Redirection::from_bits(entry.low_bits(), entry.high_bits()), entry);
        // The destination is in the *top* byte of the high half, not the bottom.
        assert_eq!(entry.high_bits(), 0x0700_0000);
        // Vector in the low byte, polarity at 13, trigger at 15, mask at 16.
        assert_eq!(entry.low_bits() & 0xFF, 0x35);
        assert_eq!(entry.low_bits() & (1 << 13), 1 << 13);
        assert_eq!(entry.low_bits() & (1 << 15), 1 << 15);
        assert_eq!(entry.low_bits() & (1 << 16), 0);
        // Delivery mode stays "fixed" - bring-up wants a predictable core, not a
        // balanced one.
        assert_eq!((entry.low_bits() >> 8) & 0b111, 0);
    }

    #[test]
    fn an_unprogrammed_entry_is_masked() {
        assert!(Redirection::masked().masked);
        assert_eq!(Redirection::masked().low_bits(), 1 << 16);
    }

    #[test]
    fn masking_one_line_leaves_its_routing_alone() {
        let mut io = io_apic(24, 0);
        let entry = Redirection {
            vector: 44,
            destination: 1,
            active_low: true,
            level_triggered: true,
            masked: false,
        };
        io.set_redirection(4, entry);
        io.set_masked(4, true);
        let back = io.redirection(4);
        assert!(back.masked);
        assert_eq!(back.vector, 44);
        assert_eq!(back.destination, 1);
        assert!(back.active_low && back.level_triggered);
        io.set_masked(4, false);
        assert_eq!(io.redirection(4), entry);
    }

    #[test]
    fn a_second_controller_addresses_its_entries_from_its_own_base() {
        // A machine with two I/O APICs numbers the second one's lines from where
        // the first left off, but its *registers* still start at index 0x10.
        // Forgetting to subtract the base programs an entry that does not exist.
        let mut io = io_apic(8, 24);
        assert!(!io.covers(23));
        assert!(io.covers(24));
        assert!(io.covers(31));
        assert!(!io.covers(32));
        io.regs.log.clear();
        io.set_redirection(24, Redirection { vector: 50, ..Redirection::masked() });
        let writes: Vec<_> = io.regs.log.iter().filter(|e| e.2).map(|e| e.0).collect();
        assert_eq!(writes, vec![0x11, 0x10], "the first entry of the second controller");
    }

    #[test]
    fn masking_everything_covers_exactly_the_entries_that_exist() {
        let mut io = io_apic(24, 0);
        io.regs.log.clear();
        io.mask_all();
        let writes: Vec<_> = io.regs.log.iter().filter(|e| e.2).map(|e| e.0).collect();
        assert_eq!(writes.len(), 48, "two registers per entry, 24 entries");
        assert_eq!(*writes.iter().max().unwrap(), 0x10 + 47);
        for gsi in 0..24 {
            assert!(io.redirection(gsi).masked, "GSI {gsi} came back unmasked");
        }
    }

    #[test]
    fn madt_flags_decode_to_polarity_and_trigger() {
        // Zero means "the bus default", which for ISA is active high and edge
        // triggered - and zero is what firmware emits most of the time, so the
        // default is the case that has to be right.
        assert_eq!(polarity_and_trigger(0), (false, false));
        // 0b01 is explicitly active high, 0b11 explicitly active low.
        assert_eq!(polarity_and_trigger(0b01), (false, false));
        assert_eq!(polarity_and_trigger(0b11), (true, false));
        // Bits 3:2 are the trigger mode, same encoding.
        assert_eq!(polarity_and_trigger(0b0100), (false, false));
        assert_eq!(polarity_and_trigger(0b1100), (false, true));
        // A PCI line: active low, level triggered.
        assert_eq!(polarity_and_trigger(0b1111), (true, true));
    }
}
