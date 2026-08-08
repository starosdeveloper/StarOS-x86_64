//! Finding the ACPI tables, and the one table phase 2.2 needs.
//!
//! The parsing is [`staros_acpi`], which is host-tested and knows nothing about
//! memory. This module is the other half: turning the physical address the
//! firmware left in the hand-off into bytes the parser can read, which on this
//! side of `ExitBootServices` means going through the linear map.
//!
//! ## Why the tables are read twice
//! Every table is variable length, and the length is *inside* the table. So a
//! header is read first from a fixed-size window, and only then is the full body
//! addressed — a walk that trusted the length before validating the header would
//! be following a number out of memory the firmware may not even have described.
//!
//! ## What is deliberately not done
//! No checksum enforcement beyond what [`staros_acpi`] already does, no AML, no
//! `\_SB` namespace. The kernel needs four facts out of ACPI at this phase —
//! where the local APIC is, where the I/O APIC is, which GSI a legacy IRQ arrives
//! on, and whether there are 8259s behind it — and every one of them is in a
//! fixed-layout table. The interpreter that the rest of ACPI requires is a phase
//! 5 problem, if ever.

use core::fmt::Write;

use staros_acpi::{Directory, Madt, Rsdp, SdtHeader};

use crate::console::Console;

/// Bytes of an SDT header. Enough to learn the signature and the real length.
const HEADER_BYTES: usize = 36;

/// The largest table this kernel will read.
///
/// A bound rather than a trust: `length` comes from firmware, and a corrupt or
/// hostile one would otherwise turn into a slice running off the end of the
/// linear map. Real MADTs are a few hundred bytes; 64 KiB is far past any of
/// them and far short of anything dangerous.
const MAX_TABLE_BYTES: usize = 64 * 1024;

/// What the kernel took out of ACPI.
#[derive(Clone, Copy, Debug)]
pub struct Facts {
    /// Physical address of the local APIC's registers.
    pub local_apic: u64,
    /// Physical address of the first I/O APIC, and the first GSI it covers.
    pub io_apic: Option<(u64, u32)>,
    /// Whether the machine has 8259s behind the APICs.
    pub has_legacy_pics: bool,
    /// How many CPUs the firmware says are startable.
    pub cpus: usize,
    /// Physical address of the first HPET block, if the machine has one.
    ///
    /// Optional in a way the APICs are not: a machine without an HPET is
    /// unusual but legal, and the consequence is only that the APIC timer has
    /// nothing to be calibrated against.
    pub hpet: Option<u64>,
    /// Physical address of the MADT, so [`gsi_for_irq`] can go back to it.
    madt: u64,
}

/// Address a physical range through the linear map.
///
/// # Safety
/// `phys .. phys + len` must lie within the linear map — that is, within RAM as
/// the memory map described it — and hold initialised bytes. ACPI tables live in
/// `AcpiReclaimable` or `AcpiNvs` ranges, which the frame pool excludes, so
/// nothing else is writing them.
unsafe fn bytes_at(phys: u64, len: usize) -> &'static [u8] {
    let virt = staros_bootinfo::phys_to_virt(phys) as *const u8;
    // SAFETY: forwarded from this function's contract.
    unsafe { core::slice::from_raw_parts(virt, len) }
}

/// Read a table whose header says how long it is.
///
/// The length field is taken out of the fixed 36-byte window **by hand**, not
/// through [`SdtHeader::parse`]. That function verifies the checksum of the
/// whole table before it returns a header, which is exactly the right thing for
/// a caller that already has the table and precisely useless for one that is
/// trying to find out how long it is: parsing a 36-byte window of a 120-byte
/// table fails every time, and the failure looks like "no MADT on this machine".
///
/// # Safety
/// As [`bytes_at`], for the header; the length is bounded before it is used.
unsafe fn table_at(phys: u64) -> Option<&'static [u8]> {
    // SAFETY: forwarded.
    let header_bytes = unsafe { bytes_at(phys, HEADER_BYTES) };
    // Offset 4, four bytes, little-endian: the total length of the table.
    let len = u32::from_le_bytes(header_bytes.get(4..8)?.try_into().ok()?) as usize;
    if !(HEADER_BYTES..=MAX_TABLE_BYTES).contains(&len) {
        return None;
    }
    // SAFETY: the length is bounded above by `MAX_TABLE_BYTES`.
    let table = unsafe { bytes_at(phys, len) };
    // *Now* the header can be parsed, which is also where the checksum is
    // checked — so a table that comes back from here is one the parser trusts.
    SdtHeader::parse(table)?;
    Some(table)
}

/// Walk the RSDT or XSDT and hand back the first table with `signature`.
///
/// # Safety
/// As [`bytes_at`].
unsafe fn find_table(rsdp_phys: u64, signature: &[u8; 4]) -> Option<&'static [u8]> {
    // The RSDP is 36 bytes in its 2.0 form and 20 in its 1.0 form; the parser
    // reads what is there and reports which.
    // SAFETY: forwarded.
    let rsdp = Rsdp::parse(unsafe { bytes_at(rsdp_phys, 36) })?;
    let (dir_phys, width) = rsdp.directory()?;
    // SAFETY: forwarded; the directory is an ordinary SDT with a header.
    let dir_bytes = unsafe { table_at(dir_phys)? };
    let dir = Directory::parse(dir_bytes, width)?;
    // An index loop rather than the iterator: the iterator borrows `dir`, which
    // is a local, and the tables it finds outlive this function.
    for i in 0..dir.len() {
        let Some(entry) = dir.entry(i) else { continue };
        // SAFETY: forwarded.
        let Some(table) = (unsafe { table_at(entry) }) else { continue };
        if SdtHeader::parse(table).is_some_and(|h| h.is(signature)) {
            return Some(table);
        }
    }
    None
}

/// Read what phase 2.2 needs out of ACPI.
///
/// Returns `None` when the firmware advertised no RSDP, or the tables do not
/// parse, or there is no MADT — all of which mean the same thing operationally:
/// this machine cannot be brought up through the APICs, and the boot must say so
/// rather than program an address it guessed.
///
/// # Safety
/// `rsdp_phys` must be the address the firmware advertised, and the linear map
/// must be live. Called after `vm::init`.
#[must_use]
pub unsafe fn discover(console: &mut Console, rsdp_phys: u64) -> Option<Facts> {
    if rsdp_phys == 0 {
        let _ = writeln!(console, "acpi: firmware advertised no RSDP");
        return None;
    }
    // SAFETY: forwarded from this function's contract.
    let madt_bytes = unsafe { find_table(rsdp_phys, b"APIC") }?;
    let madt = Madt::parse(madt_bytes)?;

    let mut ids = [0u32; 64];
    let cpus = madt.cpus(&mut ids);

    // Absent on a machine with no HPET, which is legal and only costs the APIC
    // timer its ruler.
    // SAFETY: forwarded.
    let hpet = unsafe { find_table(rsdp_phys, b"HPET") }
        .and_then(staros_acpi::Hpet::parse)
        .map(|h| h.address);

    let facts = Facts {
        local_apic: u64::from(madt.local_apic_address),
        io_apic: madt
            .first_io_apic()
            .map(|(address, gsi_base)| (u64::from(address), gsi_base)),
        has_legacy_pics: madt.has_legacy_pics,
        cpus,
        hpet,
        madt: (madt_bytes.as_ptr() as u64).wrapping_sub(staros_bootinfo::PHYS_MAP_BASE),
    };
    Some(facts)
}

impl Facts {
    /// The global system interrupt a legacy ISA IRQ actually arrives on.
    ///
    /// Goes back to the table rather than caching a map, because it is asked a
    /// handful of times during bring-up and the alternative is a fixed-size array
    /// that would have to guess how many overrides a machine can declare.
    ///
    /// The answer is not the IRQ number. On nearly every PC the timer's IRQ 0
    /// arrives as GSI 2 — the 8259 cascade line took GSI 0 first — and a kernel
    /// that programmed redirection entry 0 for the timer would configure a line
    /// nothing is attached to and hear nothing.
    ///
    /// # Safety
    /// The linear map must still be live and the MADT still where it was.
    #[must_use]
    pub unsafe fn gsi_for_irq(&self, irq: u8) -> u32 {
        // SAFETY: forwarded; `discover` already read this table successfully.
        let Some(bytes) = (unsafe { table_at(self.madt) }) else {
            return u32::from(irq);
        };
        Madt::parse(bytes).map_or(u32::from(irq), |madt| madt.gsi_for_irq(irq))
    }

    /// Polarity and trigger flags the firmware declared for `irq`, if it declared
    /// an override at all.
    ///
    /// `None` means "the bus default", which for the ISA lines this kernel cares
    /// about is active high and edge triggered.
    ///
    /// # Safety
    /// As [`Facts::gsi_for_irq`].
    #[must_use]
    pub unsafe fn override_flags(&self, irq: u8) -> Option<u16> {
        // SAFETY: forwarded.
        let bytes = unsafe { table_at(self.madt) }?;
        let madt = Madt::parse(bytes)?;
        madt.entries().find_map(|e| match e {
            staros_acpi::MadtEntry::InterruptOverride { source_irq, flags, .. }
                if source_irq == irq =>
            {
                Some(flags)
            }
            _ => None,
        })
    }

    /// Report what was found.
    pub fn describe(&self, console: &mut Console) {
        let _ = writeln!(
            console,
            "acpi: madt at {:#x}, {} cpu(s), local apic at {:#x}, legacy pics {}",
            self.madt,
            self.cpus,
            self.local_apic,
            if self.has_legacy_pics { "present" } else { "absent" },
        );
        match self.io_apic {
            Some((address, gsi_base)) => {
                let _ = writeln!(
                    console,
                    "acpi: io apic at {address:#x}, first gsi {gsi_base}"
                );
            }
            None => {
                let _ = writeln!(console, "acpi: no I/O APIC in the MADT");
            }
        }
        match self.hpet {
            Some(address) => {
                let _ = writeln!(console, "acpi: hpet at {address:#x}");
            }
            None => {
                let _ = writeln!(console, "acpi: no HPET - the APIC timer has nothing to calibrate against");
            }
        }
    }
}
