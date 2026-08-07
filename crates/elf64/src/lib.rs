//! A read-only ELF64 program-header parser: the loader's view of a kernel image.
//!
//! The UEFI loader reads `kernel` off the ESP as an opaque byte slice and has to
//! answer three questions before it can jump: where does the image want to live,
//! which bytes go where, and with what rights. That is all this crate does —
//! header validation and a walk of the `PT_LOAD` segments. No sections, no
//! symbols, no relocations, no dynamic linking: the kernel is a non-PIE
//! executable under the `kernel` code model, so there is nothing to relocate.
//!
//! ## Why this is a separate crate
//! Everything here is pure byte-slicing over data that arrives from a FAT
//! partition, which is to say from outside the kernel's control. That makes it
//! exactly the kind of code whose bugs are silent — an off-by-one in a bounds
//! check reads firmware memory and loads it as kernel text — and exactly the kind
//! this workspace insists on testing on the host. The aarch64 tree carries an
//! equivalent parser inside `crates/kernel/src/elf.rs` for EL0 programs; this one
//! is separate because it runs in a *different binary* (the loader), before the
//! kernel exists at all.
//!
//! ## What it refuses
//! Totality is the whole point: every read is bounds-checked, every rejection has
//! its own reason, and no input produces a panic or an out-of-range slice. A
//! truncated or hostile image must fail with a name the loader can print, because
//! at that moment printing is the only diagnostic that exists.

#![cfg_attr(not(test), no_std)]

/// `PT_LOAD` — a segment that must be placed in memory.
const PT_LOAD: u32 = 1;
/// `e_machine` for x86-64.
const EM_X86_64: u16 = 62;
/// `e_type` for a non-PIE executable. `ET_DYN` is deliberately rejected: it would
/// need relocation processing, which the `kernel` code model exists to avoid.
const ET_EXEC: u16 = 2;
/// Page size every mapping decision is made in.
pub const PAGE_SIZE: u64 = 4096;

/// Segment permission bit `PF_X`.
const PF_X: u32 = 1;
/// Segment permission bit `PF_W`.
const PF_W: u32 = 2;
/// Segment permission bit `PF_R`.
const PF_R: u32 = 4;

/// Why an image was rejected.
///
/// One variant per check rather than a single `Invalid`: the loader prints this
/// and then halts, so the variant name *is* the bug report. "Not an ELF at all"
/// and "an ELF for the wrong machine" send you to completely different places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// The four magic bytes are not `\x7fELF`.
    NotElf,
    /// `EI_CLASS` is not `ELFCLASS64`. A 32-bit kernel image on the ESP.
    NotElf64,
    /// `EI_DATA` is not `ELFDATA2LSB`.
    NotLittleEndian,
    /// `e_machine` is not [`EM_X86_64`] — most likely the aarch64 kernel copied
    /// onto a PC's ESP, which is a mistake worth naming exactly.
    WrongMachine,
    /// `e_type` is not `ET_EXEC`.
    WrongType,
    /// The file is shorter than the 64-byte ELF header.
    TruncatedHeader,
    /// `e_phentsize` is smaller than a program header, or the program-header
    /// table runs past the end of the file.
    TruncatedProgramHeaders,
    /// A segment's `p_offset..p_offset + p_filesz` lies outside the file.
    SegmentOutOfImage,
    /// A segment claims more file bytes than memory bytes, which cannot be
    /// loaded under any interpretation.
    FileLargerThanMemory,
    /// A `PT_LOAD` segment's `p_vaddr` is not page-aligned. Refused rather than
    /// rounded: two segments sharing a page cannot both get their own rights, and
    /// W^X that silently degrades to RWX is worse than a failed boot.
    UnalignedSegment,
    /// The image has no `PT_LOAD` segments — nothing to load.
    NoLoadableSegments,
    /// The image spans an address range that overflows a `u64`.
    SpanOverflow,
}

impl ElfError {
    /// A short, printable explanation. `Display` is avoided so the crate stays
    /// free of `core::fmt` machinery in a binary that may have none.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotElf => "not an ELF file",
            Self::NotElf64 => "not ELF64 (32-bit image?)",
            Self::NotLittleEndian => "not little-endian",
            Self::WrongMachine => "wrong machine (not x86-64 — aarch64 kernel on this ESP?)",
            Self::WrongType => "not ET_EXEC (position-independent image?)",
            Self::TruncatedHeader => "truncated ELF header",
            Self::TruncatedProgramHeaders => "truncated program headers",
            Self::SegmentOutOfImage => "segment lies outside the file",
            Self::FileLargerThanMemory => "segment p_filesz > p_memsz",
            Self::UnalignedSegment => "segment p_vaddr is not page-aligned",
            Self::NoLoadableSegments => "no PT_LOAD segments",
            Self::SpanOverflow => "image span overflows the address space",
        }
    }
}

/// The rights a segment asks for, decoded from `p_flags`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights {
    /// `PF_R`.
    pub read: bool,
    /// `PF_W`.
    pub write: bool,
    /// `PF_X`.
    pub exec: bool,
}

impl Rights {
    /// Decode `p_flags`. Unknown bits are ignored — they are reserved for the
    /// OS/processor and carry no meaning for placement.
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        Self {
            read: flags & PF_R != 0,
            write: flags & PF_W != 0,
            exec: flags & PF_X != 0,
        }
    }

    /// Whether the segment is both writable and executable. The loader checks
    /// this so a W^X violation is reported at load time, where it is a build
    /// mistake, rather than discovered later as an exploit primitive.
    #[must_use]
    pub const fn is_wx(self) -> bool {
        self.write && self.exec
    }
}

/// One `PT_LOAD` segment, resolved against the image bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Virtual address the segment must appear at (`p_vaddr`), page-aligned.
    pub vaddr: u64,
    /// The bytes to copy (`p_filesz` of them, starting at `p_offset`).
    pub file: &'a [u8],
    /// Total in-memory size (`p_memsz`). Bytes beyond `file.len()` are the
    /// zero-filled tail — `.bss` and, in this kernel, the boot stack.
    pub memsz: u64,
    /// Rights decoded from `p_flags`.
    pub rights: Rights,
}

impl Segment<'_> {
    /// Number of 4 KiB pages the segment occupies in memory.
    #[must_use]
    pub const fn pages(&self) -> u64 {
        self.memsz.div_ceil(PAGE_SIZE)
    }
}

/// Read a little-endian value at `off`, or `None` if it does not fit.
fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)?.try_into().ok().map(u16::from_le_bytes)
}
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)?.try_into().ok().map(u32::from_le_bytes)
}
fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off.checked_add(8)?)?.try_into().ok().map(u64::from_le_bytes)
}

/// A validated ELF64 executable borrowing the raw image bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf<'a> {
    image: &'a [u8],
    entry: u64,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

impl<'a> Elf<'a> {
    /// Validate `image` as an x86-64 ELF64 executable.
    ///
    /// Header-level checks only; segment-level ones happen during iteration, so
    /// that a caller which only wants the entry point does not pay for a full
    /// walk, and a caller which does walk gets each failure attributed to the
    /// segment that caused it.
    ///
    /// # Errors
    /// Returns the specific [`ElfError`] for the first check that fails.
    pub fn parse(image: &'a [u8]) -> Result<Self, ElfError> {
        if image.len() < 64 {
            return Err(ElfError::TruncatedHeader);
        }
        if image.get(0..4) != Some(b"\x7fELF") {
            return Err(ElfError::NotElf);
        }
        if image[4] != 2 {
            return Err(ElfError::NotElf64);
        }
        if image[5] != 1 {
            return Err(ElfError::NotLittleEndian);
        }
        // e_type@16, e_machine@18, e_entry@24, e_phoff@32, e_phentsize@54,
        // e_phnum@56. The length check above guarantees all of these are present.
        if read_u16(image, 16) != Some(ET_EXEC) {
            return Err(ElfError::WrongType);
        }
        if read_u16(image, 18) != Some(EM_X86_64) {
            return Err(ElfError::WrongMachine);
        }

        let entry = read_u64(image, 24).ok_or(ElfError::TruncatedHeader)?;
        let phoff = read_u64(image, 32).ok_or(ElfError::TruncatedHeader)?;
        let phentsize = read_u16(image, 54).ok_or(ElfError::TruncatedHeader)? as usize;
        let phnum = read_u16(image, 56).ok_or(ElfError::TruncatedHeader)? as usize;

        // A program header is 56 bytes; entries may be larger (padding is legal)
        // but never smaller, or the fields we read would overlap the next entry.
        if phentsize < 56 {
            return Err(ElfError::TruncatedProgramHeaders);
        }
        let phoff: usize = phoff.try_into().map_err(|_| ElfError::TruncatedProgramHeaders)?;
        let table_len = phentsize
            .checked_mul(phnum)
            .ok_or(ElfError::TruncatedProgramHeaders)?;
        let table_end = phoff
            .checked_add(table_len)
            .ok_or(ElfError::TruncatedProgramHeaders)?;
        if table_end > image.len() {
            return Err(ElfError::TruncatedProgramHeaders);
        }

        Ok(Self { image, entry, phoff, phentsize, phnum })
    }

    /// The entry point (`e_entry`) — the virtual address to jump to.
    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Iterate the `PT_LOAD` segments in program-header order.
    ///
    /// Each item is a `Result`, because a malformed segment must stop the load
    /// rather than be skipped: an image missing one of its segments would boot
    /// far enough to be confusing.
    #[must_use]
    pub const fn segments(&self) -> Segments<'a> {
        Segments {
            image: self.image,
            phoff: self.phoff,
            phentsize: self.phentsize,
            phnum: self.phnum,
            index: 0,
        }
    }

    /// The contiguous physical block the image needs: `(base_vaddr, bytes)`,
    /// page-aligned outwards.
    ///
    /// The loader allocates one block of this size and places every segment at
    /// `phys_base + (vaddr - base_vaddr)`, which keeps the virtual→physical
    /// offset constant across the whole image. That is what lets the kernel later
    /// derive its own physical base from a single number in [`BootInfo`] instead
    /// of a per-segment table.
    ///
    /// [`BootInfo`]: https://docs.rs/staros-bootinfo
    ///
    /// # Errors
    /// Propagates any segment error, and reports [`ElfError::NoLoadableSegments`]
    /// for an image with nothing to load.
    pub fn load_span(&self) -> Result<(u64, u64), ElfError> {
        let mut lo = u64::MAX;
        let mut hi = 0u64;
        for seg in self.segments() {
            let seg = seg?;
            let end = seg.vaddr.checked_add(seg.memsz).ok_or(ElfError::SpanOverflow)?;
            lo = lo.min(seg.vaddr);
            hi = hi.max(end);
        }
        if lo == u64::MAX {
            return Err(ElfError::NoLoadableSegments);
        }
        // `lo` is page-aligned already (segments are checked), so only the tail
        // needs rounding.
        let hi = hi.checked_next_multiple_of(PAGE_SIZE).ok_or(ElfError::SpanOverflow)?;
        Ok((lo, hi - lo))
    }
}

/// Iterator over an image's `PT_LOAD` segments. See [`Elf::segments`].
#[derive(Clone, Copy, Debug)]
pub struct Segments<'a> {
    image: &'a [u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    index: usize,
}

impl<'a> Iterator for Segments<'a> {
    type Item = Result<Segment<'a>, ElfError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.phnum {
            let ph = self.phoff + self.index * self.phentsize;
            self.index += 1;

            // Elf64_Phdr: p_type@0, p_flags@4, p_offset@8, p_vaddr@16,
            // p_paddr@24, p_filesz@32, p_memsz@40, p_align@48.
            let (Some(p_type), Some(p_flags)) = (read_u32(self.image, ph), read_u32(self.image, ph + 4))
            else {
                return Some(Err(ElfError::TruncatedProgramHeaders));
            };
            if p_type != PT_LOAD {
                continue;
            }
            let (Some(offset), Some(vaddr), Some(filesz), Some(memsz)) = (
                read_u64(self.image, ph + 8),
                read_u64(self.image, ph + 16),
                read_u64(self.image, ph + 32),
                read_u64(self.image, ph + 40),
            ) else {
                return Some(Err(ElfError::TruncatedProgramHeaders));
            };

            if filesz > memsz {
                return Some(Err(ElfError::FileLargerThanMemory));
            }
            if !vaddr.is_multiple_of(PAGE_SIZE) {
                return Some(Err(ElfError::UnalignedSegment));
            }

            // usize on a 32-bit host would truncate; the conversion is checked so
            // the tests can run anywhere.
            let (Ok(offset), Ok(filesz_us)) = (usize::try_from(offset), usize::try_from(filesz))
            else {
                return Some(Err(ElfError::SegmentOutOfImage));
            };
            let Some(end) = offset.checked_add(filesz_us) else {
                return Some(Err(ElfError::SegmentOutOfImage));
            };
            let Some(file) = self.image.get(offset..end) else {
                return Some(Err(ElfError::SegmentOutOfImage));
            };

            return Some(Ok(Segment {
                vaddr,
                file,
                memsz,
                rights: Rights::from_flags(p_flags),
            }));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic ELF64 image: header + `phdrs` + the raw segment bytes
    /// appended at `data_off`. Returns the whole file.
    ///
    /// Deliberately hand-assembled rather than produced by a linker, so a test
    /// can corrupt one field at a time and know that field is the only variable.
    struct Builder {
        entry: u64,
        machine: u16,
        etype: u16,
        class: u8,
        data: u8,
        magic: [u8; 4],
        phentsize: u16,
        /// (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)
        phdrs: Vec<(u32, u32, u64, u64, u64, u64)>,
        /// Bytes appended after the program-header table.
        tail: Vec<u8>,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                entry: 0xFFFF_FFFF_8000_0000,
                machine: EM_X86_64,
                etype: ET_EXEC,
                class: 2,
                data: 1,
                magic: *b"\x7fELF",
                phentsize: 56,
                phdrs: Vec::new(),
                tail: Vec::new(),
            }
        }

        fn load(mut self, offset: u64, vaddr: u64, filesz: u64, memsz: u64, flags: u32) -> Self {
            self.phdrs.push((PT_LOAD, flags, offset, vaddr, filesz, memsz));
            self
        }

        fn note(mut self, offset: u64, filesz: u64) -> Self {
            // PT_NOTE = 4: a non-loadable header the walk must skip.
            self.phdrs.push((4, PF_R, offset, 0, filesz, filesz));
            self
        }

        fn build(self) -> Vec<u8> {
            let phoff = 64u64;
            let mut out = vec![0u8; 64];
            out[0..4].copy_from_slice(&self.magic);
            out[4] = self.class;
            out[5] = self.data;
            out[6] = 1; // EI_VERSION
            out[16..18].copy_from_slice(&self.etype.to_le_bytes());
            out[18..20].copy_from_slice(&self.machine.to_le_bytes());
            out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
            out[24..32].copy_from_slice(&self.entry.to_le_bytes());
            out[32..40].copy_from_slice(&phoff.to_le_bytes());
            out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
            out[54..56].copy_from_slice(&self.phentsize.to_le_bytes());
            out[56..58].copy_from_slice(&(self.phdrs.len() as u16).to_le_bytes());

            for (ty, flags, offset, vaddr, filesz, memsz) in &self.phdrs {
                // Always laid out as a real 56-byte Elf64_Phdr, then resized to
                // `phentsize`: a *smaller* entry size is exactly the malformed
                // case one test needs, and it must truncate rather than panic.
                let mut ph = vec![0u8; 56];
                ph[0..4].copy_from_slice(&ty.to_le_bytes());
                ph[4..8].copy_from_slice(&flags.to_le_bytes());
                ph[8..16].copy_from_slice(&offset.to_le_bytes());
                ph[16..24].copy_from_slice(&vaddr.to_le_bytes());
                ph[24..32].copy_from_slice(&vaddr.to_le_bytes()); // p_paddr
                ph[32..40].copy_from_slice(&filesz.to_le_bytes());
                ph[40..48].copy_from_slice(&memsz.to_le_bytes());
                ph[48..56].copy_from_slice(&PAGE_SIZE.to_le_bytes()); // p_align
                ph.resize(self.phentsize as usize, 0);
                out.extend_from_slice(&ph);
            }
            out.extend_from_slice(&self.tail);
            out
        }
    }

    /// A three-segment image shaped like the real linker script: RX text,
    /// R rodata, RW data — each page-aligned, the last with a `.bss` tail.
    fn kernel_like() -> Vec<u8> {
        const BASE: u64 = 0xFFFF_FFFF_8000_0000;
        let mut b = Builder::new()
            .load(0x1000, BASE, 0x1000, 0x1000, PF_R | PF_X)
            .load(0x2000, BASE + 0x1000, 0x1000, 0x1000, PF_R)
            .load(0x3000, BASE + 0x2000, 0x0800, 0x3000, PF_R | PF_W);
        // Pad to 0x4000 so every declared file range exists, with recognisable
        // bytes per segment.
        b.tail = vec![0u8; 0x4000 - 64 - 3 * 56];
        let mut img = b.build();
        img[0x1000] = 0xAA;
        img[0x2000] = 0xBB;
        img[0x3000] = 0xCC;
        img
    }

    #[test]
    fn parses_a_kernel_shaped_image() {
        let img = kernel_like();
        let elf = Elf::parse(&img).expect("valid image");
        assert_eq!(elf.entry(), 0xFFFF_FFFF_8000_0000);
        let segs: Vec<_> = elf.segments().map(|s| s.unwrap()).collect();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].rights, Rights { read: true, write: false, exec: true });
        assert_eq!(segs[1].rights, Rights { read: true, write: false, exec: false });
        assert_eq!(segs[2].rights, Rights { read: true, write: true, exec: false });
        assert_eq!(segs[0].file[0], 0xAA);
        assert_eq!(segs[1].file[0], 0xBB);
        assert_eq!(segs[2].file[0], 0xCC);
    }

    #[test]
    fn bss_tail_is_memsz_minus_filesz() {
        let img = kernel_like();
        let elf = Elf::parse(&img).unwrap();
        let data = elf.segments().nth(2).unwrap().unwrap();
        assert_eq!(data.file.len(), 0x800);
        assert_eq!(data.memsz, 0x3000);
        // The tail the loader must zero: everything the file does not supply.
        assert_eq!(data.memsz - data.file.len() as u64, 0x2800);
        assert_eq!(data.pages(), 3);
    }

    #[test]
    fn load_span_covers_every_segment_and_rounds_up() {
        const BASE: u64 = 0xFFFF_FFFF_8000_0000;
        let img = kernel_like();
        let elf = Elf::parse(&img).unwrap();
        let (base, size) = elf.load_span().unwrap();
        assert_eq!(base, BASE);
        // Last segment ends at +0x2000 + 0x3000 = 0x5000, already page-aligned.
        assert_eq!(size, 0x5000);
    }

    #[test]
    fn load_span_rounds_a_ragged_tail_up_to_a_page() {
        let mut b = Builder::new().load(64 + 56, 0x1000, 1, 1, PF_R);
        b.tail = vec![0u8; 1];
        let img = b.build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.load_span().unwrap(), (0x1000, PAGE_SIZE));
    }

    #[test]
    fn non_load_headers_are_skipped_not_counted() {
        let mut b = Builder::new()
            .note(64 + 2 * 56, 4)
            .load(64 + 2 * 56, 0x1000, 4, 4, PF_R);
        b.tail = vec![0u8; 4];
        let img = b.build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().count(), 1);
        assert_eq!(elf.load_span().unwrap(), (0x1000, PAGE_SIZE));
    }

    #[test]
    fn an_image_with_no_load_segments_is_rejected_by_span_not_by_parse() {
        // Parsing succeeds — the header is well-formed. It is the *load* that has
        // nothing to do, and saying so at that point is what lets the loader
        // report "no PT_LOAD" rather than "not an ELF".
        let img = Builder::new().note(64 + 56, 0).build();
        let elf = Elf::parse(&img).expect("header is valid");
        assert_eq!(elf.load_span(), Err(ElfError::NoLoadableSegments));
    }

    #[test]
    fn rejects_a_foreign_machine_by_name() {
        let mut b = Builder::new();
        b.machine = 183; // EM_AARCH64 — the aarch64 kernel on a PC's ESP
        let img = b.build();
        assert_eq!(Elf::parse(&img), Err(ElfError::WrongMachine));
    }

    #[test]
    fn rejects_the_wrong_class_endianness_type_and_magic_separately() {
        let mut b = Builder::new();
        b.class = 1;
        let img = b.build();
        assert_eq!(Elf::parse(&img), Err(ElfError::NotElf64));

        let mut b = Builder::new();
        b.data = 2;
        let img = b.build();
        assert_eq!(Elf::parse(&img), Err(ElfError::NotLittleEndian));

        let mut b = Builder::new();
        b.etype = 3; // ET_DYN
        let img = b.build();
        assert_eq!(Elf::parse(&img), Err(ElfError::WrongType));

        let mut b = Builder::new();
        b.magic = *b"MZ\x00\x00"; // the loader itself, copied over the kernel
        let img = b.build();
        assert_eq!(Elf::parse(&img), Err(ElfError::NotElf));
    }

    #[test]
    fn truncating_the_header_at_every_length_is_rejected_not_panicked() {
        let img = kernel_like();
        for n in 0..64 {
            assert_eq!(
                Elf::parse(&img[..n]),
                Err(ElfError::TruncatedHeader),
                "length {n} must be rejected as a short header",
            );
        }
    }

    #[test]
    fn truncating_the_program_header_table_is_rejected_at_every_length() {
        let img = kernel_like();
        let table_end = 64 + 3 * 56;
        for n in 64..table_end {
            assert_eq!(
                Elf::parse(&img[..n]),
                Err(ElfError::TruncatedProgramHeaders),
                "length {n} cuts the program-header table",
            );
        }
        // One byte more than the table is enough to parse; the segments then fail
        // individually, which is the distinction the error split exists for.
        let elf = Elf::parse(&img[..table_end]).expect("table is complete");
        assert_eq!(elf.segments().next().unwrap(), Err(ElfError::SegmentOutOfImage));
    }

    #[test]
    fn a_segment_pointing_past_the_file_is_rejected() {
        let img = Builder::new().load(64 + 56, 0x1000, 0x1000, 0x1000, PF_R).build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().next().unwrap(), Err(ElfError::SegmentOutOfImage));
        assert_eq!(elf.load_span(), Err(ElfError::SegmentOutOfImage));
    }

    #[test]
    fn a_segment_offset_that_overflows_usize_is_rejected() {
        let img = Builder::new().load(u64::MAX - 8, 0x1000, 16, 16, PF_R).build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().next().unwrap(), Err(ElfError::SegmentOutOfImage));
    }

    #[test]
    fn filesz_larger_than_memsz_is_rejected() {
        let mut b = Builder::new().load(64 + 56, 0x1000, 8, 4, PF_R);
        b.tail = vec![0u8; 8];
        let img = b.build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().next().unwrap(), Err(ElfError::FileLargerThanMemory));
    }

    #[test]
    fn an_unaligned_segment_is_refused_rather_than_rounded() {
        let mut b = Builder::new().load(64 + 56, 0x1001, 4, 4, PF_R);
        b.tail = vec![0u8; 4];
        let img = b.build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().next().unwrap(), Err(ElfError::UnalignedSegment));
    }

    #[test]
    fn a_phentsize_below_the_real_header_size_is_rejected() {
        let mut b = Builder::new().load(64 + 56, 0x1000, 0, 0, PF_R);
        b.phentsize = 48;
        let img = b.build();
        assert_eq!(Elf::parse(&img), Err(ElfError::TruncatedProgramHeaders));
    }

    #[test]
    fn a_larger_phentsize_still_parses_padding_is_legal() {
        let mut b = Builder::new().load(64 + 72, 0x1000, 4, 4, PF_R | PF_X);
        b.phentsize = 72;
        b.tail = vec![0u8; 4];
        let img = b.build();
        let elf = Elf::parse(&img).unwrap();
        let seg = elf.segments().next().unwrap().unwrap();
        assert_eq!(seg.vaddr, 0x1000);
        assert!(seg.rights.exec);
    }

    #[test]
    fn a_segment_reaching_past_the_address_space_is_a_span_overflow() {
        let img = Builder::new()
            .load(64 + 56, 0xFFFF_FFFF_FFFF_F000, 0, u64::MAX, PF_R)
            .build();
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.load_span(), Err(ElfError::SpanOverflow));
    }

    #[test]
    fn wx_segments_are_detectable_so_the_loader_can_refuse_them() {
        assert!(Rights::from_flags(PF_R | PF_W | PF_X).is_wx());
        assert!(!Rights::from_flags(PF_R | PF_X).is_wx());
        assert!(!Rights::from_flags(PF_R | PF_W).is_wx());
    }

    #[test]
    fn every_error_has_a_distinct_printable_reason() {
        let all = [
            ElfError::NotElf,
            ElfError::NotElf64,
            ElfError::NotLittleEndian,
            ElfError::WrongMachine,
            ElfError::WrongType,
            ElfError::TruncatedHeader,
            ElfError::TruncatedProgramHeaders,
            ElfError::SegmentOutOfImage,
            ElfError::FileLargerThanMemory,
            ElfError::UnalignedSegment,
            ElfError::NoLoadableSegments,
            ElfError::SpanOverflow,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(!a.as_str().is_empty());
            for b in &all[i + 1..] {
                assert_ne!(a.as_str(), b.as_str(), "two errors share a message");
            }
        }
    }
}
