//! ACPI tables — the PC's device tree, as pure logic.
//!
//! On aarch64 the kernel asks the machine what it is by walking a flattened
//! device tree ([`staros_fdt`]). A PC answers the same questions through ACPI: a
//! chain of tables in physical memory, found from a **root pointer** the firmware
//! advertises, each self-describing and each checksummed. Where the DTB says
//! `intc: GICv3, dist 0x8000000`, ACPI's MADT says `Local APIC id 0, IO APIC at
//! 0xFEC00000, GSI base 0` — different words, the same job, and the same rule:
//! **discovered, never assumed**.
//!
//! This crate is the parsing half only. It takes byte slices and returns
//! structure; it does not map memory, does not touch MMIO, and knows nothing
//! about the kernel. That is what makes it host-testable against synthetic
//! tables — the same split as `fdt`, `cpio`, `videocore` and `iommu` in the
//! aarch64 tree, and for the same reason: **the bugs live in the layout**, and a
//! layout bug on a PC costs you the machine before it has any way to print.
//!
//! ## What it deliberately does not do
//! There is no AML interpreter here, and there will not be one. AML is a
//! bytecode with its own virtual machine, and everything this kernel needs for
//! bring-up — CPUs, interrupt controllers, the PCIe config window, the timers —
//! lives in the *static* tables. Power management and hot-plug need AML; they are
//! not phase-1 problems, and pretending otherwise would import an interpreter
//! into a microkernel that exists to keep such things in user space.
//!
//! ## Safety model
//! Every parse is length-checked against the slice it was given, and every table
//! is checksum-verified before its contents are believed. Malformed input yields
//! `None`, never a panic and never a read past the end — a property the tests
//! assert by feeding in truncated and corrupted tables byte by byte.

#![cfg_attr(not(test), no_std)]

/// Signature of the Root System Description Pointer, at the head of the 20-byte
/// (revision 0) or 36-byte (revision 2+) structure the firmware advertises.
pub const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// Length of the revision-0 RSDP, which is also the range its checksum covers.
const RSDP_V1_LEN: usize = 20;
/// Length of the revision-2 RSDP, and the range its *extended* checksum covers.
const RSDP_V2_LEN: usize = 36;

/// The header every ACPI system description table starts with.
const SDT_HEADER_LEN: usize = 36;

/// Read a little-endian `u32` at `off`, or `None` if it does not fit.
fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian `u64` at `off`, or `None` if it does not fit.
///
/// ACPI tables are **not** aligned in any way the compiler can rely on — the
/// MADT's entries in particular are a packed byte stream — so every multi-byte
/// read here goes through byte assembly rather than a pointer cast. An unaligned
/// `u64` read is undefined behaviour in Rust even on x86, where the hardware
/// tolerates it.
fn u64_at(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Whether the bytes sum to zero modulo 256 — ACPI's checksum for every table.
///
/// A wrapping sum, deliberately: the check is defined over `u8` arithmetic, and
/// a widening sum would accept tables the firmware considers corrupt.
#[must_use]
pub fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// The Root System Description Pointer: where the table chain begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    /// ACPI revision: 0 for 1.0 (32-bit RSDT only), 2+ for 2.0 (64-bit XSDT).
    pub revision: u8,
    /// Physical address of the RSDT (32-bit pointers). Zero if absent.
    pub rsdt: u32,
    /// Physical address of the XSDT (64-bit pointers). Zero on revision 0.
    pub xsdt: u64,
    /// The six-byte OEM id, for logging.
    pub oem_id: [u8; 6],
}

impl Rsdp {
    /// Parse and validate an RSDP from the bytes at the address the firmware
    /// advertised.
    ///
    /// Returns `None` if the signature is wrong, the buffer is short, or either
    /// checksum fails. Revision 2 has **two** checksums — the first covering the
    /// original 20 bytes and the second the whole 36 — and both must pass;
    /// checking only the first is the classic way to accept a torn table.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < RSDP_V1_LEN || &buf[0..8] != RSDP_SIGNATURE {
            return None;
        }
        if !checksum_ok(&buf[..RSDP_V1_LEN]) {
            return None;
        }
        let revision = buf[15];
        let rsdt = u32_at(buf, 16)?;
        let mut oem_id = [0u8; 6];
        oem_id.copy_from_slice(&buf[9..15]);

        let xsdt = if revision >= 2 {
            if buf.len() < RSDP_V2_LEN {
                return None;
            }
            // The extended checksum covers the *full* structure, whose length the
            // table itself declares; trust the declared length only if it fits.
            let len = u32_at(buf, 20)? as usize;
            if !(RSDP_V2_LEN..=buf.len()).contains(&len) || !checksum_ok(&buf[..len]) {
                return None;
            }
            u64_at(buf, 24)?
        } else {
            0
        };

        Some(Self { revision, rsdt, xsdt, oem_id })
    }

    /// The address of the table directory to walk, preferring the 64-bit XSDT.
    ///
    /// Returns `(address, entry_width)`. The width matters: RSDT entries are
    /// 4 bytes and XSDT entries 8, and reading one as the other yields addresses
    /// that are plausible enough to fault on rather than obviously wrong.
    #[must_use]
    pub const fn directory(&self) -> Option<(u64, usize)> {
        if self.revision >= 2 && self.xsdt != 0 {
            Some((self.xsdt, 8))
        } else if self.rsdt != 0 {
            Some((self.rsdt as u64, 4))
        } else {
            None
        }
    }
}

/// The 36-byte header shared by every system description table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SdtHeader {
    /// Four-character table signature, e.g. `APIC`, `MCFG`, `HPET`.
    pub signature: [u8; 4],
    /// Total length of the table in bytes, header included.
    pub length: u32,
    /// Table revision.
    pub revision: u8,
    /// OEM table id, for logging.
    pub oem_table_id: [u8; 8],
}

impl SdtHeader {
    /// Parse a header from the start of `buf` **and verify the whole table's
    /// checksum**, so a caller that gets a header back may believe the body.
    ///
    /// Returns `None` if the buffer is shorter than the declared length — which
    /// is the check that turns a corrupt `length` field into a rejected table
    /// rather than a read off the end of the mapping.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SDT_HEADER_LEN {
            return None;
        }
        let length = u32_at(buf, 4)? as usize;
        if length < SDT_HEADER_LEN || length > buf.len() || !checksum_ok(&buf[..length]) {
            return None;
        }
        let mut signature = [0u8; 4];
        signature.copy_from_slice(&buf[0..4]);
        let mut oem_table_id = [0u8; 8];
        oem_table_id.copy_from_slice(&buf[16..24]);
        Some(Self { signature, length: length as u32, revision: buf[8], oem_table_id })
    }

    /// Whether this table's signature is `sig`.
    #[must_use]
    pub fn is(&self, sig: &[u8; 4]) -> bool {
        &self.signature == sig
    }
}

/// The table directory (XSDT or RSDT): an SDT header followed by an array of
/// physical addresses of other tables.
///
/// The kernel maps this, wraps it here, and asks for tables by signature. The
/// *addresses* are returned rather than the tables themselves, because resolving
/// one means mapping physical memory — which is the kernel's job, not this
/// crate's.
#[derive(Clone, Copy, Debug)]
pub struct Directory<'a> {
    entries: &'a [u8],
    width: usize,
}

impl<'a> Directory<'a> {
    /// Wrap the bytes of an XSDT (`width` 8) or RSDT (`width` 4).
    ///
    /// Returns `None` unless the header parses, the checksum passes and the
    /// signature is the one the width implies — an XSDT read as an RSDT would
    /// otherwise produce a directory of half-addresses.
    #[must_use]
    pub fn parse(buf: &'a [u8], width: usize) -> Option<Self> {
        let header = SdtHeader::parse(buf)?;
        let expected: &[u8; 4] = if width == 8 { b"XSDT" } else { b"RSDT" };
        if !header.is(expected) {
            return None;
        }
        let entries = buf.get(SDT_HEADER_LEN..header.length as usize)?;
        Some(Self { entries, width })
    }

    /// How many table pointers the directory holds. A trailing partial entry —
    /// a length that is not a whole number of pointers — is ignored rather than
    /// read.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len() / self.width
    }

    /// Whether the directory is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The physical address of the `i`-th table.
    #[must_use]
    pub fn entry(&self, i: usize) -> Option<u64> {
        let off = i.checked_mul(self.width)?;
        if self.width == 8 {
            u64_at(self.entries, off)
        } else {
            u32_at(self.entries, off).map(u64::from)
        }
    }

    /// Every table address in order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.len()).filter_map(|i| self.entry(i))
    }
}

// ---------------------------------------------------------------------------
// MADT — the interrupt topology (ACPI's answer to the GIC node)
// ---------------------------------------------------------------------------

/// One entry of the Multiple APIC Description Table.
///
/// Only the variants bring-up needs are decoded; anything else is reported as
/// [`MadtEntry::Other`] with its type byte, so an unknown entry advances the
/// walk correctly instead of stopping it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadtEntry {
    /// A CPU. The count of *enabled* ones is how many cores SMP bring-up may
    /// start; a disabled entry describes a socket that is present but not
    /// startable, and treating it as a CPU means waiting forever for it.
    LocalApic {
        /// Processor id as the firmware's namespace calls it.
        acpi_id: u8,
        /// Local APIC id — the value an INIT-SIPI is addressed to.
        apic_id: u8,
        /// Whether this processor may be started.
        enabled: bool,
    },
    /// An I/O APIC: the thing that routes device interrupts to CPUs.
    IoApic {
        /// This controller's id.
        id: u8,
        /// Physical address of its registers.
        address: u32,
        /// The first global system interrupt this controller covers.
        gsi_base: u32,
    },
    /// A legacy IRQ that does not map to the GSI of the same number — e.g. the
    /// PIT's IRQ 0 arriving as GSI 2, which is true on most PCs and is exactly
    /// the kind of fact that must be read rather than assumed.
    InterruptOverride {
        /// Source bus; 0 means ISA, which is the only one that occurs.
        bus: u8,
        /// The legacy IRQ number as software names it.
        source_irq: u8,
        /// The global system interrupt it actually arrives on.
        gsi: u32,
        /// Polarity and trigger-mode bits.
        flags: u16,
    },
    /// A local APIC NMI line.
    LocalApicNmi {
        /// Processor this applies to; `0xFF` means all of them.
        acpi_id: u8,
        /// Polarity and trigger-mode bits.
        flags: u16,
        /// Which local interrupt input (`LINT0`/`LINT1`) carries the NMI.
        lint: u8,
    },
    /// A CPU with a 32-bit APIC id (x2APIC), used above 255 cores.
    LocalX2Apic {
        /// 32-bit local APIC id.
        apic_id: u32,
        /// Processor id as the firmware's namespace calls it.
        acpi_id: u32,
        /// Whether this processor may be started.
        enabled: bool,
    },
    /// Any other entry type, carried through by its type byte so an unknown
    /// entry advances the walk instead of stopping it.
    Other {
        /// The raw type byte.
        entry_type: u8,
    },
}

/// The Multiple APIC Description Table (signature `APIC`).
#[derive(Clone, Copy, Debug)]
pub struct Madt<'a> {
    body: &'a [u8],
    /// Physical address of the local APIC registers, as the table reports it.
    pub local_apic_address: u32,
    /// Bit 0 of the flags: the machine also has legacy 8259 PICs, which must be
    /// masked off before the APICs are trusted or their spurious interrupts
    /// arrive as unexpected vectors.
    pub has_legacy_pics: bool,
}

impl<'a> Madt<'a> {
    /// Parse a MADT from its bytes.
    #[must_use]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let header = SdtHeader::parse(buf)?;
        if !header.is(b"APIC") {
            return None;
        }
        let local_apic_address = u32_at(buf, 36)?;
        let flags = u32_at(buf, 40)?;
        let body = buf.get(44..header.length as usize)?;
        Some(Self { body, local_apic_address, has_legacy_pics: flags & 1 != 0 })
    }

    /// Walk the entries.
    ///
    /// Each entry is `[type, length, ...]`, and a zero or oversized `length` is
    /// where a naive walk spins forever or runs off the end — both are treated
    /// as end-of-table here.
    pub fn entries(&self) -> MadtIter<'a> {
        MadtIter { body: self.body, off: 0 }
    }

    /// APIC ids of every *enabled* CPU, in table order, written into `out`.
    /// Returns how many were found — which may exceed `out.len()`, so a caller
    /// can tell "16 CPUs, I have room for 8" from "8 CPUs".
    pub fn cpus(&self, out: &mut [u32]) -> usize {
        let mut n = 0;
        for e in self.entries() {
            let id = match e {
                MadtEntry::LocalApic { apic_id, enabled: true, .. } => u32::from(apic_id),
                MadtEntry::LocalX2Apic { apic_id, enabled: true, .. } => apic_id,
                _ => continue,
            };
            if let Some(slot) = out.get_mut(n) {
                *slot = id;
            }
            n += 1;
        }
        n
    }

    /// The first I/O APIC, as `(address, gsi_base)`. Bring-up needs one; a
    /// multi-socket machine has several and the rest are handled later.
    #[must_use]
    pub fn first_io_apic(&self) -> Option<(u32, u32)> {
        self.entries().find_map(|e| match e {
            MadtEntry::IoApic { address, gsi_base, .. } => Some((address, gsi_base)),
            _ => None,
        })
    }

    /// The global system interrupt a legacy ISA IRQ actually arrives on,
    /// honouring any override entry. Defaults to identity when the firmware
    /// declares no override, which is what the specification requires.
    #[must_use]
    pub fn gsi_for_irq(&self, irq: u8) -> u32 {
        self.entries()
            .find_map(|e| match e {
                MadtEntry::InterruptOverride { source_irq, gsi, .. } if source_irq == irq => {
                    Some(gsi)
                }
                _ => None,
            })
            .unwrap_or(u32::from(irq))
    }
}

/// Iterator over MADT entries.
#[derive(Clone, Copy, Debug)]
pub struct MadtIter<'a> {
    body: &'a [u8],
    off: usize,
}

impl Iterator for MadtIter<'_> {
    type Item = MadtEntry;

    fn next(&mut self) -> Option<MadtEntry> {
        let entry_type = *self.body.get(self.off)?;
        let len = *self.body.get(self.off + 1)? as usize;
        // A length below the two-byte header, or one that overruns the table,
        // cannot be advanced past: stop rather than spin or read out of bounds.
        if len < 2 || self.off + len > self.body.len() {
            return None;
        }
        let e = &self.body[self.off..self.off + len];
        self.off += len;

        Some(match entry_type {
            0 if len >= 8 => MadtEntry::LocalApic {
                acpi_id: e[2],
                apic_id: e[3],
                enabled: u32_at(e, 4)? & 1 != 0,
            },
            1 if len >= 12 => MadtEntry::IoApic {
                id: e[2],
                address: u32_at(e, 4)?,
                gsi_base: u32_at(e, 8)?,
            },
            2 if len >= 10 => MadtEntry::InterruptOverride {
                bus: e[2],
                source_irq: e[3],
                gsi: u32_at(e, 4)?,
                flags: u16::from_le_bytes([e[8], e[9]]),
            },
            4 if len >= 6 => MadtEntry::LocalApicNmi {
                acpi_id: e[2],
                flags: u16::from_le_bytes([e[3], e[4]]),
                lint: e[5],
            },
            9 if len >= 16 => MadtEntry::LocalX2Apic {
                apic_id: u32_at(e, 4)?,
                acpi_id: u32_at(e, 12)?,
                enabled: u32_at(e, 8)? & 1 != 0,
            },
            other => MadtEntry::Other { entry_type: other },
        })
    }
}

// ---------------------------------------------------------------------------
// MCFG — where PCIe configuration space lives
// ---------------------------------------------------------------------------

/// One PCIe ECAM window from the MCFG table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcamWindow {
    /// Physical base of the configuration space region.
    pub base: u64,
    /// PCI segment group.
    pub segment: u16,
    /// First bus number this window covers.
    pub bus_start: u8,
    /// Last bus number this window covers.
    pub bus_end: u8,
}

impl EcamWindow {
    /// Physical address of a function's 4 KiB configuration space:
    /// `base + ((bus - bus_start) << 20) + (dev << 15) + (func << 12)`.
    ///
    /// Returns `None` if the bus is outside this window — the check that stops a
    /// stray enumeration from reading another window's memory, or the firmware's.
    #[must_use]
    pub const fn config_address(&self, bus: u8, dev: u8, func: u8) -> Option<u64> {
        if bus < self.bus_start || bus > self.bus_end || dev >= 32 || func >= 8 {
            return None;
        }
        let offset = ((bus - self.bus_start) as u64) << 20
            | (dev as u64) << 15
            | (func as u64) << 12;
        Some(self.base + offset)
    }
}

/// The PCI Express memory-mapped configuration table (signature `MCFG`).
#[derive(Clone, Copy, Debug)]
pub struct Mcfg<'a> {
    body: &'a [u8],
}

impl<'a> Mcfg<'a> {
    /// Parse an MCFG from its bytes.
    #[must_use]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let header = SdtHeader::parse(buf)?;
        if !header.is(b"MCFG") {
            return None;
        }
        // 36-byte SDT header + 8 reserved bytes, then 16-byte entries.
        let body = buf.get(44..header.length as usize)?;
        Some(Self { body })
    }

    /// The configuration windows this machine exposes.
    pub fn windows(&self) -> impl Iterator<Item = EcamWindow> + '_ {
        (0..self.body.len() / 16).filter_map(move |i| {
            let e = self.body.get(i * 16..i * 16 + 16)?;
            Some(EcamWindow {
                base: u64_at(e, 0)?,
                segment: u16::from_le_bytes([e[8], e[9]]),
                bus_start: e[10],
                bus_end: e[11],
            })
        })
    }
}

// ---------------------------------------------------------------------------
// HPET — a timer that exists on every PC and does not need calibration
// ---------------------------------------------------------------------------

/// The High Precision Event Timer description table (signature `HPET`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpet {
    /// Physical base of the HPET's registers.
    pub address: u64,
    /// Which HPET block this is, when a machine has more than one.
    pub number: u8,
    /// Minimum tick the hardware guarantees, in femtoseconds — the period below
    /// which a one-shot comparator may be missed.
    pub min_tick: u16,
}

impl Hpet {
    /// Parse an HPET table from its bytes.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let header = SdtHeader::parse(buf)?;
        if !header.is(b"HPET") || (header.length as usize) < 56 {
            return None;
        }
        // Offset 40 begins a Generic Address Structure; its address field is at
        // +4 within it, i.e. table offset 44.
        Some(Self {
            address: u64_at(buf, 44)?,
            number: buf[52],
            min_tick: u16::from_le_bytes([buf[53], buf[54]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set the checksum byte of a table so the whole thing sums to zero — what
    /// real firmware does, and what lets these tests exercise the *checked* path
    /// rather than a path that happens to skip the check.
    fn fix_checksum(table: &mut [u8], checksum_off: usize, len: usize) {
        table[checksum_off] = 0;
        let sum = table[..len].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        table[checksum_off] = sum.wrapping_neg();
    }

    fn rsdp_v2(xsdt: u64) -> [u8; RSDP_V2_LEN] {
        let mut r = [0u8; RSDP_V2_LEN];
        r[0..8].copy_from_slice(RSDP_SIGNATURE);
        r[9..15].copy_from_slice(b"STAROS");
        r[15] = 2; // revision
        r[16..20].copy_from_slice(&0xDEAD_0000u32.to_le_bytes()); // RSDT
        r[20..24].copy_from_slice(&(RSDP_V2_LEN as u32).to_le_bytes());
        r[24..32].copy_from_slice(&xsdt.to_le_bytes());
        fix_checksum(&mut r, 8, RSDP_V1_LEN); // v1 checksum: first 20 bytes
        fix_checksum(&mut r, 32, RSDP_V2_LEN); // extended checksum: all 36
        // Fixing the extended checksum must not disturb the first one.
        assert!(checksum_ok(&r[..RSDP_V1_LEN]));
        r
    }

    /// Build a table: signature, body after the 36-byte header, checksum fixed.
    fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let len = SDT_HEADER_LEN + body.len();
        let mut t = vec![0u8; len];
        t[0..4].copy_from_slice(sig);
        t[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        t[8] = 1; // revision
        t[10..16].copy_from_slice(b"STAROS");
        t[16..24].copy_from_slice(b"STARPC01");
        t[SDT_HEADER_LEN..].copy_from_slice(body);
        fix_checksum(&mut t, 9, len);
        t
    }

    #[test]
    fn a_v2_rsdp_prefers_the_xsdt() {
        let r = Rsdp::parse(&rsdp_v2(0x7FFF_0000)).expect("valid RSDP");
        assert_eq!(r.revision, 2);
        assert_eq!(r.xsdt, 0x7FFF_0000);
        assert_eq!(&r.oem_id, b"STAROS");
        assert_eq!(r.directory(), Some((0x7FFF_0000, 8)), "64-bit entries");
    }

    #[test]
    fn a_v1_rsdp_falls_back_to_the_rsdt_with_narrow_entries() {
        let mut r = [0u8; RSDP_V1_LEN];
        r[0..8].copy_from_slice(RSDP_SIGNATURE);
        r[15] = 0; // revision 0: no XSDT at all
        r[16..20].copy_from_slice(&0x000E_0000u32.to_le_bytes());
        fix_checksum(&mut r, 8, RSDP_V1_LEN);
        let p = Rsdp::parse(&r).expect("valid v1 RSDP");
        assert_eq!(p.xsdt, 0);
        assert_eq!(p.directory(), Some((0x000E_0000, 4)), "32-bit entries");
    }

    #[test]
    fn a_v2_rsdp_with_a_broken_extended_checksum_is_rejected() {
        // The first 20 bytes still sum correctly — this is exactly the torn table
        // that a single-checksum parser accepts.
        let mut r = rsdp_v2(0x7FFF_0000);
        r[33] ^= 0xff;
        assert!(checksum_ok(&r[..RSDP_V1_LEN]), "the v1 checksum still passes");
        assert_eq!(Rsdp::parse(&r), None);
    }

    #[test]
    fn a_wrong_signature_or_a_short_buffer_is_not_an_rsdp() {
        let mut r = rsdp_v2(1);
        r[0] = b'X';
        assert_eq!(Rsdp::parse(&r), None);
        assert_eq!(Rsdp::parse(&rsdp_v2(1)[..RSDP_V1_LEN - 1]), None);
    }

    #[test]
    fn an_xsdt_lists_its_tables() {
        let mut body = Vec::new();
        for addr in [0x1000u64, 0x2000, 0x3000] {
            body.extend_from_slice(&addr.to_le_bytes());
        }
        let t = table(b"XSDT", &body);
        let d = Directory::parse(&t, 8).expect("valid XSDT");
        assert_eq!(d.len(), 3);
        assert!(!d.is_empty());
        assert_eq!(d.iter().collect::<Vec<_>>(), vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn an_xsdt_read_as_an_rsdt_is_refused_rather_than_halved() {
        let t = table(b"XSDT", &0x1234_5678_9abc_def0u64.to_le_bytes());
        assert_eq!(Directory::parse(&t, 4).map(|d| d.len()), None);
    }

    #[test]
    fn a_trailing_partial_entry_is_ignored_not_read() {
        // 8-byte entry plus 3 stray bytes: one whole pointer, no over-read.
        let mut body = 0x4000u64.to_le_bytes().to_vec();
        body.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let t = table(b"XSDT", &body);
        let d = Directory::parse(&t, 8).expect("valid XSDT");
        assert_eq!(d.len(), 1);
        assert_eq!(d.entry(1), None);
    }

    #[test]
    fn a_corrupt_table_checksum_is_rejected() {
        let mut t = table(b"XSDT", &0x1000u64.to_le_bytes());
        t[30] ^= 0xff;
        assert_eq!(SdtHeader::parse(&t), None);
        assert!(Directory::parse(&t, 8).is_none());
    }

    #[test]
    fn a_length_field_longer_than_the_buffer_is_rejected() {
        // The check that turns a corrupt length into a refusal instead of a read
        // past the end of the mapping.
        let mut t = table(b"XSDT", &0x1000u64.to_le_bytes());
        t[4..8].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        assert_eq!(SdtHeader::parse(&t), None);
    }

    /// A MADT shaped like a real four-core PC: LAPIC ×4 (one disabled), one
    /// IO APIC, and the IRQ0 → GSI2 override every PC actually has.
    fn madt() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0xFEE0_0000u32.to_le_bytes()); // local APIC address
        body.extend_from_slice(&1u32.to_le_bytes()); // flags: legacy PICs present
        for (acpi, apic, enabled) in [(0u8, 0u8, 1u32), (1, 1, 1), (2, 2, 1), (3, 3, 0)] {
            body.extend_from_slice(&[0, 8, acpi, apic]);
            body.extend_from_slice(&enabled.to_le_bytes());
        }
        body.extend_from_slice(&[1, 12, 2, 0]); // IO APIC, id 2
        body.extend_from_slice(&0xFEC0_0000u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // GSI base 0
        body.extend_from_slice(&[2, 10, 0, 0]); // override: bus 0, IRQ 0
        body.extend_from_slice(&2u32.to_le_bytes()); // -> GSI 2
        body.extend_from_slice(&[0, 0]); // flags
        table(b"APIC", &body)
    }

    #[test]
    fn a_madt_yields_the_enabled_cpus_only() {
        let t = madt();
        let m = Madt::parse(&t).expect("valid MADT");
        assert_eq!(m.local_apic_address, 0xFEE0_0000);
        assert!(m.has_legacy_pics, "8259s must be masked before trusting the APICs");

        let mut cpus = [0u32; 8];
        assert_eq!(m.cpus(&mut cpus), 3, "the disabled CPU is not startable");
        assert_eq!(&cpus[..3], &[0, 1, 2]);
    }

    #[test]
    fn cpus_reports_the_true_count_even_when_the_buffer_is_too_small() {
        let t = madt();
        let m = Madt::parse(&t).unwrap();
        let mut only_two = [0u32; 2];
        assert_eq!(m.cpus(&mut only_two), 3, "count is not clipped to the buffer");
        assert_eq!(only_two, [0, 1]);
    }

    #[test]
    fn the_io_apic_and_the_irq0_override_are_read_not_assumed() {
        let t = madt();
        let m = Madt::parse(&t).unwrap();
        assert_eq!(m.first_io_apic(), Some((0xFEC0_0000, 0)));
        assert_eq!(m.gsi_for_irq(0), 2, "the PIT arrives on GSI 2 on a real PC");
        assert_eq!(m.gsi_for_irq(4), 4, "no override means identity");
    }

    #[test]
    fn an_x2apic_entry_is_decoded() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xFEE0_0000u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[9, 16, 0, 0]); // x2APIC entry
        body.extend_from_slice(&300u32.to_le_bytes()); // apic id past 255
        body.extend_from_slice(&1u32.to_le_bytes()); // enabled
        body.extend_from_slice(&7u32.to_le_bytes()); // acpi id
        let t = table(b"APIC", &body);
        let m = Madt::parse(&t).unwrap();
        let mut cpus = [0u32; 4];
        assert_eq!(m.cpus(&mut cpus), 1);
        assert_eq!(cpus[0], 300);
    }

    #[test]
    fn a_zero_length_madt_entry_ends_the_walk_instead_of_spinning() {
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&[0, 0, 0, 0]); // type 0, length 0 — unadvanceable
        let t = table(b"APIC", &body);
        let m = Madt::parse(&t).unwrap();
        assert_eq!(m.entries().count(), 0);
    }

    #[test]
    fn an_entry_claiming_to_run_past_the_table_is_dropped() {
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&[1, 200, 0, 0]); // length 200 in a 4-byte tail
        let t = table(b"APIC", &body);
        let m = Madt::parse(&t).unwrap();
        assert_eq!(m.entries().count(), 0);
        assert_eq!(m.first_io_apic(), None);
    }

    #[test]
    fn an_unknown_entry_type_advances_the_walk_rather_than_stopping_it() {
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&[0x42, 6, 0, 0, 0, 0]); // unknown, well-formed
        body.extend_from_slice(&[1, 12, 5, 0]); // then a real IO APIC
        body.extend_from_slice(&0xFEC0_1000u32.to_le_bytes());
        body.extend_from_slice(&24u32.to_le_bytes());
        let t = table(b"APIC", &body);
        let m = Madt::parse(&t).unwrap();
        assert_eq!(m.entries().count(), 2);
        assert_eq!(m.first_io_apic(), Some((0xFEC0_1000, 24)));
    }

    #[test]
    fn an_mcfg_yields_ecam_windows_and_config_addresses() {
        let mut body = vec![0u8; 8]; // reserved
        body.extend_from_slice(&0xE000_0000u64.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // segment
        body.extend_from_slice(&[0, 255]); // buses 0..=255
        body.extend_from_slice(&[0, 0, 0, 0]); // reserved
        let t = table(b"MCFG", &body);
        let m = Mcfg::parse(&t).expect("valid MCFG");
        let w: Vec<_> = m.windows().collect();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].base, 0xE000_0000);
        assert_eq!(w[0].bus_end, 255);
        // bus 1, device 2, function 3
        assert_eq!(
            w[0].config_address(1, 2, 3),
            Some(0xE000_0000 + (1 << 20) + (2 << 15) + (3 << 12)),
        );
    }

    #[test]
    fn a_bus_outside_the_window_has_no_config_address() {
        let w = EcamWindow { base: 0xE000_0000, segment: 0, bus_start: 8, bus_end: 15 };
        assert_eq!(w.config_address(7, 0, 0), None);
        assert_eq!(w.config_address(16, 0, 0), None);
        assert_eq!(w.config_address(8, 32, 0), None, "device numbers are 5 bits");
        assert_eq!(w.config_address(8, 0, 8), None, "function numbers are 3 bits");
        // The first bus of a window is at its base, not at base + bus<<20.
        assert_eq!(w.config_address(8, 0, 0), Some(0xE000_0000));
    }

    #[test]
    fn an_hpet_table_gives_its_register_base() {
        // Body starts at table offset 36: the Generic Address Structure occupies
        // offsets 40..52, and its address field sits at +4 within it (table 44).
        let mut body = vec![0u8; 20];
        body[8..16].copy_from_slice(&0xFED0_0000u64.to_le_bytes()); // GAS address
        body[16] = 0; // HPET number (table offset 52)
        body[17..19].copy_from_slice(&14318u16.to_le_bytes());
        let t = table(b"HPET", &body);
        let h = Hpet::parse(&t).expect("valid HPET");
        assert_eq!(h.address, 0xFED0_0000);
        assert_eq!(h.min_tick, 14318);
    }

    #[test]
    fn tables_are_matched_by_signature_not_by_position() {
        let apic = madt();
        assert!(Mcfg::parse(&apic).is_none());
        assert!(Hpet::parse(&apic).is_none());
        assert!(Directory::parse(&apic, 8).is_none());
    }

    #[test]
    fn truncating_any_table_at_any_point_never_panics() {
        // Total decoding, the way the fdt and videocore crates assert it: every
        // prefix of every table must be refused or parsed, never crash.
        for t in [madt(), table(b"MCFG", &[0u8; 24]), table(b"XSDT", &[0u8; 16])] {
            for n in 0..t.len() {
                let prefix = &t[..n];
                let _ = SdtHeader::parse(prefix);
                let _ = Directory::parse(prefix, 8);
                if let Some(m) = Madt::parse(prefix) {
                    let _ = m.entries().count();
                }
                if let Some(m) = Mcfg::parse(prefix) {
                    let _ = m.windows().count();
                }
                let _ = Hpet::parse(prefix);
            }
        }
    }

    #[test]
    fn corrupting_any_single_byte_never_panics() {
        let base = madt();
        for i in 0..base.len() {
            let mut t = base.clone();
            t[i] ^= 0xff;
            if let Some(m) = Madt::parse(&t) {
                let _ = m.entries().count();
                let mut cpus = [0u32; 4];
                let _ = m.cpus(&mut cpus);
                let _ = m.gsi_for_irq(0);
            }
        }
    }
}
