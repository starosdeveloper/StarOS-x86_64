//! The loader → kernel hand-off contract.
//!
//! On aarch64 this role is played by the device tree: the bootloader leaves a
//! blob in memory, puts its address in `x0`, and the kernel discovers the machine
//! by parsing it. A PC has no such single artefact. The firmware knows the memory
//! map, the framebuffer and where the ACPI tables are, but it knows them through
//! **boot services**, which stop existing the moment the kernel takes over
//! (`ExitBootServices`). Whatever the kernel needs must therefore be *collected
//! before* that call and handed across in a structure both sides agree on.
//!
//! This crate is that structure, and nothing else — no UEFI calls, no MMIO, no
//! architecture. The loader fills it in while boot services are alive; the kernel
//! validates and reads it afterwards. Being pure data means both halves of the
//! contract are host-testable, which matters more here than usual: a mistake in
//! this struct is a mistake made *before* the kernel has any way to print.
//!
//! ## Why not just re-use a device tree
//! Nothing stops a loader from synthesising a DTB, and it would let both trees
//! share `staros-fdt`. It is rejected because it would be *invented* structure:
//! the firmware's memory map is not a device tree, and translating it into one
//! adds a lossy step between two formats the kernel then has to trust equally.
//! The PC discovers its devices through ACPI (see [`staros_acpi`]), and this
//! struct carries only the handful of facts ACPI cannot answer.
//!
//! ## Stability
//! [`BootInfo::MAGIC`] and [`BootInfo::VERSION`] are checked on arrival. The
//! loader and the kernel are built together from this workspace, so a mismatch
//! means a stale binary on the ESP — the single most likely PC boot failure, and
//! one that otherwise presents as a triple fault with no output at all.

#![cfg_attr(not(test), no_std)]

/// Virtual base of the linear map of physical memory.
///
/// The loader builds this map and the kernel inherits it, so the constant is one
/// of the hand-off's terms — as much as any field of [`BootInfo`] — and lives
/// here rather than in either binary. It matched by luck once already, which is
/// exactly the kind of luck that stops holding after a refactor.
///
/// See `docs/SPEC.md` §3.1 for the whole layout.
pub const PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Virtual base of the kernel image, matching `crates/arch-x86_64/linker.ld`.
///
/// The loader checks the image it loaded is linked here before it maps anything;
/// disagreement between the two means a kernel running at an address its own code
/// does not believe in, which fails in ways that look like hardware faults.
pub const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;

/// The address a physical one is reachable at through the linear map.
///
/// Saturating rather than wrapping: an address so high that the linear map cannot
/// reach it must not silently alias something low.
#[must_use]
pub const fn phys_to_virt(phys: u64) -> u64 {
    PHYS_MAP_BASE.saturating_add(phys)
}

/// What the firmware said about one range of physical memory.
///
/// Deliberately coarser than the UEFI memory-type enum: the kernel only needs to
/// know what it may *take*. Everything that is not plainly free is `Reserved` or
/// one of the two ACPI flavours, and the distinction between those matters
/// exactly once (see [`MemoryKind::AcpiReclaimable`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryKind {
    /// Free for the kernel's frame allocator.
    Usable = 0,
    /// Firmware, MMIO, or anything else the kernel must never allocate.
    Reserved = 1,
    /// Holds ACPI tables. Becomes usable *after* the kernel has parsed
    /// everything it wants out of them — and not one instruction sooner, which
    /// is why it is a distinct kind rather than merged into `Reserved`.
    AcpiReclaimable = 2,
    /// ACPI non-volatile storage: must be preserved across sleep states. Never
    /// usable.
    AcpiNvs = 3,
    /// The loader's own image and data, plus anything it allocated for the
    /// kernel (the boot info itself, the memory map, the kernel image).
    /// Reclaimable once the kernel has copied out what it needs.
    LoaderReclaimable = 4,
    /// Physically present but reported bad by firmware.
    BadMemory = 5,
}

impl MemoryKind {
    /// Whether the frame allocator may take this range *immediately* at boot.
    ///
    /// Conservative on purpose: `AcpiReclaimable` and `LoaderReclaimable` are
    /// excluded even though their names promise otherwise, because "reclaimable"
    /// is a statement about the future, and the frame pool is built in the past.
    #[must_use]
    pub const fn usable_at_boot(self) -> bool {
        matches!(self, Self::Usable)
    }
}

/// One entry of the physical memory map.
///
/// `#[repr(C)]` because the loader writes it and the kernel reads it from a
/// different compilation unit; the layout is the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MemoryRegion {
    /// Physical base address. Page-aligned.
    pub start: u64,
    /// Length in bytes. A multiple of the page size.
    pub len: u64,
    /// What the firmware said this range is.
    pub kind: MemoryKind,
    /// Padding, so the struct's size is the same on every compiler version.
    _pad: u32,
}

impl MemoryRegion {
    /// Build a region. `len` of zero is legal (firmware does emit empty ranges)
    /// and is filtered out by the iterators rather than rejected here.
    #[must_use]
    pub const fn new(start: u64, len: u64, kind: MemoryKind) -> Self {
        Self { start, len, kind, _pad: 0 }
    }

    /// One past the last byte, saturating instead of wrapping — a firmware entry
    /// that claims to reach past the end of the address space must not silently
    /// become an empty region.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    /// Whether this region contains `addr`.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }
}

/// A linear framebuffer the firmware already set up (UEFI GOP).
///
/// This is the PC's answer to the VideoCore mailbox on a Pi: the display is
/// *already* lit when the kernel starts, and writing pixels needs no driver, no
/// PCIe enumeration and no GPU knowledge. It is therefore the first output
/// channel, exactly as on the Pi — and for the same reason, since a PC has no
/// guaranteed serial port at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Framebuffer {
    /// Physical base address of the pixel buffer.
    pub phys: u64,
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in pixels.
    pub height: u32,
    /// Bytes per row. **Not** `width * bytes_per_pixel` in general — firmware
    /// pads rows, and assuming otherwise produces a sheared image, the classic
    /// first-pixel bug.
    pub stride: u32,
    /// Bits per pixel (32 for every format below).
    pub bpp: u32,
    /// Channel order.
    pub format: PixelFormat,
    _pad: u32,
}

impl Framebuffer {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(
        phys: u64,
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Self {
        Self { phys, width, height, stride, bpp: 32, format, _pad: 0 }
    }

    /// Total bytes the buffer occupies: `height * stride`, which is what must be
    /// mapped — using `height * width * 4` under-maps every padded mode.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.height as u64 * self.stride as u64
    }

    /// Whether the geometry is self-consistent: non-empty, and a stride at least
    /// as wide as the visible pixels. Firmware that reports otherwise is not to
    /// be drawn on.
    #[must_use]
    pub const fn is_sane(&self) -> bool {
        self.phys != 0
            && self.width > 0
            && self.height > 0
            && self.stride >= self.width * 4
    }
}

/// Channel order of a 32-bit pixel, as UEFI GOP reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// Blue in the lowest byte: `0x00RRGGBB` little-endian. GOP's
    /// `PixelBlueGreenRedReserved8BitPerColor`, and what nearly every PC reports.
    Bgrx8888 = 0,
    /// Red in the lowest byte. GOP's `PixelRedGreenBlueReserved8BitPerColor`.
    Rgbx8888 = 1,
}

impl PixelFormat {
    /// The same byte order, in the drawing crate's vocabulary.
    ///
    /// **The names invert, and that is not a mistake in either crate.** GOP names
    /// a format by its channels in *memory order* — `Bgrx8888` means blue is the
    /// byte at offset 0. `staros_framebuffer` names one by the packed 32-bit word
    /// on a little-endian machine — `xrgb8888` means the word is `0x00RRGGBB`,
    /// whose lowest byte is blue. Same pixel, opposite-looking name.
    ///
    /// Getting it backwards is invisible in every test that checks addressing and
    /// obvious the moment anything is drawn: the console comes up with red and
    /// blue swapped. Hence a conversion with a test rather than a `match` written
    /// out at the call site.
    #[must_use]
    pub const fn to_framebuffer(self) -> staros_framebuffer::PixelFormat {
        match self {
            Self::Bgrx8888 => staros_framebuffer::PixelFormat::xrgb8888(),
            Self::Rgbx8888 => staros_framebuffer::PixelFormat::xbgr8888(),
        }
    }
}

/// Everything the kernel needs that it cannot discover for itself once the
/// firmware is gone.
///
/// Passed by pointer in `RDI` (System V's first argument register), so the
/// kernel entry point is an ordinary `extern "C" fn(&BootInfo) -> !`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BootInfo {
    /// Must equal [`BootInfo::MAGIC`].
    pub magic: u64,
    /// Must equal [`BootInfo::VERSION`].
    pub version: u32,
    /// Number of entries in the memory map.
    pub memory_map_len: u32,
    /// Physical address of a `[MemoryRegion; memory_map_len]`.
    pub memory_map: u64,
    /// The firmware framebuffer, if there was one. `phys == 0` means none.
    pub framebuffer: Framebuffer,
    /// Physical address of the ACPI RSDP the firmware advertised, or 0.
    /// Everything else about the machine — CPUs, APICs, ECAM, timers — is
    /// reached from here (see [`staros_acpi`]).
    pub rsdp: u64,
    /// Physical base of an initramfs the loader placed, or 0.
    pub initrd: u64,
    /// Length of that initramfs in bytes.
    pub initrd_len: u64,
    /// Physical base of the kernel image as loaded, so the kernel can exclude
    /// itself from the frame pool without guessing from linker symbols.
    pub kernel_phys: u64,
    /// Bytes of physical memory the kernel image occupies.
    pub kernel_len: u64,
}

/// Why a [`BootInfo`] was rejected.
///
/// Distinct variants rather than a bool: this is the first thing that can go
/// wrong on a PC boot, and "which check failed" is the whole diagnosis when the
/// only output device is one the boot info itself describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoError {
    /// The magic did not match — this is not a `BootInfo` at all.
    BadMagic,
    /// The magic matched but the version did not: a stale loader or kernel on
    /// the ESP, the single most common PC boot failure.
    BadVersion,
    /// The memory map is absent or empty; there is nothing to allocate from.
    NoMemoryMap,
}

impl BootInfo {
    /// `"STAROSPC"` as little-endian bytes.
    pub const MAGIC: u64 = u64::from_le_bytes(*b"STAROSPC");

    /// Bumped whenever a field's meaning or position changes.
    pub const VERSION: u32 = 1;

    /// Check that this structure is one of ours and is self-consistent.
    ///
    /// # Errors
    /// See [`BootInfoError`].
    pub const fn validate(&self) -> Result<(), BootInfoError> {
        if self.magic != Self::MAGIC {
            return Err(BootInfoError::BadMagic);
        }
        if self.version != Self::VERSION {
            return Err(BootInfoError::BadVersion);
        }
        if self.memory_map == 0 || self.memory_map_len == 0 {
            return Err(BootInfoError::NoMemoryMap);
        }
        Ok(())
    }

    /// The framebuffer, if the firmware provided a usable one.
    #[must_use]
    pub const fn framebuffer(&self) -> Option<Framebuffer> {
        if self.framebuffer.is_sane() { Some(self.framebuffer) } else { None }
    }

    /// The initramfs, as `(phys, len)`, if one was loaded.
    #[must_use]
    pub const fn initrd(&self) -> Option<(u64, u64)> {
        if self.initrd != 0 && self.initrd_len != 0 {
            Some((self.initrd, self.initrd_len))
        } else {
            None
        }
    }
}

/// Facts derived from a memory map, computed without touching the memory itself.
///
/// Split out from [`BootInfo`] so the arithmetic — which is where the mistakes
/// live — can be tested on the host against hand-written maps, including the
/// shapes real firmware produces: empty entries, out-of-order entries, a usable
/// range that starts at physical zero, and one that claims to run past the end
/// of the address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MemoryStats {
    /// Sum of all `Usable` ranges, in bytes.
    pub usable_bytes: u64,
    /// Sum of every range the firmware described, in bytes.
    pub total_bytes: u64,
    /// The largest single usable range, or `None` if there is none.
    pub largest_usable: Option<(u64, u64)>,
    /// Highest address any region reaches, device apertures included.
    pub highest_address: u64,
    /// Highest address reached by anything that is actually *memory*.
    ///
    /// This, not [`MemoryStats::highest_address`], is how far the linear map has
    /// to span. The distinction is not academic: a q35 machine parks twelve
    /// gigabytes of reserved device space at 1012 GiB, and counting it built a
    /// terabyte of mappings for a machine with 512 MiB of RAM.
    ///
    /// [`MemoryKind::Reserved`] is the kind that is excluded, and it is the only
    /// one that can be either — UEFI's reserved *memory* and its memory-mapped
    /// *I/O* both arrive as `Reserved`, so a range that might be an aperture is
    /// treated as one. The cost of being wrong in this direction is a page of
    /// firmware memory the kernel has to map deliberately; in the other, it is
    /// gigabytes of page tables.
    pub highest_ram: u64,
}

/// Summarise a memory map.
///
/// Zero-length regions are skipped: firmware emits them, and letting one become
/// `largest_usable` would hand the allocator a pool it cannot allocate from.
#[must_use]
pub fn summarise(regions: &[MemoryRegion]) -> MemoryStats {
    let mut stats = MemoryStats::default();
    for r in regions {
        if r.len == 0 {
            continue;
        }
        stats.total_bytes = stats.total_bytes.saturating_add(r.len);
        stats.highest_address = stats.highest_address.max(r.end());
        if r.kind != MemoryKind::Reserved {
            stats.highest_ram = stats.highest_ram.max(r.end());
        }
        if r.kind.usable_at_boot() {
            stats.usable_bytes = stats.usable_bytes.saturating_add(r.len);
            let better = match stats.largest_usable {
                Some((_, len)) => r.len > len,
                None => true,
            };
            if better {
                stats.largest_usable = Some((r.start, r.len));
            }
        }
    }
    stats
}

/// The largest usable range that does not overlap any of `exclusions`, as
/// `(start, len)`.
///
/// This is how the frame pool is placed. The kernel image, the boot info, the
/// memory map itself and an initramfs all sit *inside* memory the firmware calls
/// usable, so "largest usable range" is not an answer until they are carved out.
/// Each exclusion splits a candidate in two and the larger half survives.
#[must_use]
pub fn largest_free_run(
    regions: &[MemoryRegion],
    exclusions: &[(u64, u64)],
) -> Option<(u64, u64)> {
    let mut best: Option<(u64, u64)> = None;
    for r in regions.iter().filter(|r| r.kind.usable_at_boot() && r.len > 0) {
        let mut candidates = [(r.start, r.end()); 1];
        // Apply exclusions one at a time, keeping only the larger surviving half.
        // Two exclusions inside one region can therefore lose the middle piece —
        // acceptable for placing one pool, and stated rather than hidden.
        for &(ex_start, ex_len) in exclusions {
            let ex_end = ex_start.saturating_add(ex_len);
            let (start, end) = candidates[0];
            if ex_end <= start || ex_start >= end {
                continue; // disjoint
            }
            let left = (start, ex_start.min(end));
            let right = (ex_end.max(start), end);
            let left_len = left.1.saturating_sub(left.0);
            let right_len = right.1.saturating_sub(right.0);
            candidates[0] = if left_len >= right_len { left } else { right };
        }
        let (start, end) = candidates[0];
        let len = end.saturating_sub(start);
        if len > 0 && best.is_none_or(|(_, best_len)| len > best_len) {
            best = Some((start, len));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn boot_info() -> BootInfo {
        BootInfo {
            magic: BootInfo::MAGIC,
            version: BootInfo::VERSION,
            memory_map_len: 3,
            memory_map: 0x1000,
            framebuffer: Framebuffer::new(0xE000_0000, 1920, 1080, 1920 * 4, PixelFormat::Bgrx8888),
            rsdp: 0x000F_0000,
            initrd: 0,
            initrd_len: 0,
            kernel_phys: 0x10_0000,
            kernel_len: 512 * 1024,
        }
    }

    #[test]
    fn a_well_formed_boot_info_validates() {
        assert_eq!(boot_info().validate(), Ok(()));
    }

    #[test]
    fn each_rejection_is_named_separately() {
        let mut bi = boot_info();
        bi.magic = 0;
        assert_eq!(bi.validate(), Err(BootInfoError::BadMagic));

        let mut bi = boot_info();
        bi.version = BootInfo::VERSION + 1;
        assert_eq!(bi.validate(), Err(BootInfoError::BadVersion));

        let mut bi = boot_info();
        bi.memory_map_len = 0;
        assert_eq!(bi.validate(), Err(BootInfoError::NoMemoryMap));
    }

    #[test]
    fn magic_is_the_ascii_we_think_it_is() {
        assert_eq!(BootInfo::MAGIC.to_le_bytes(), *b"STAROSPC");
    }

    #[test]
    fn a_padded_framebuffer_is_measured_by_its_stride() {
        // 1366x768 is the classic mode whose stride is not width*4.
        let fb = Framebuffer::new(0xE000_0000, 1366, 768, 1376 * 4, PixelFormat::Bgrx8888);
        assert!(fb.is_sane());
        assert_eq!(fb.bytes(), 768 * 1376 * 4);
        assert_ne!(fb.bytes(), 768 * 1366 * 4, "measuring by width under-maps");
    }

    #[test]
    fn insane_framebuffers_are_rejected_rather_than_drawn_on() {
        let no_base = Framebuffer::new(0, 800, 600, 3200, PixelFormat::Bgrx8888);
        assert!(!no_base.is_sane());
        let too_narrow = Framebuffer::new(0xE000_0000, 800, 600, 800, PixelFormat::Bgrx8888);
        assert!(!too_narrow.is_sane(), "stride below one row of pixels");
        let empty = Framebuffer::new(0xE000_0000, 0, 600, 3200, PixelFormat::Bgrx8888);
        assert!(!empty.is_sane());
    }

    #[test]
    fn summary_skips_empty_regions_and_finds_the_biggest() {
        let map = [
            MemoryRegion::new(0, 0, MemoryKind::Usable), // firmware really emits these
            MemoryRegion::new(0x1000, 64 * MIB, MemoryKind::Usable),
            MemoryRegion::new(0x1000 + 64 * MIB, 16 * MIB, MemoryKind::Reserved),
            MemoryRegion::new(0x1_0000_0000, 512 * MIB, MemoryKind::Usable),
            MemoryRegion::new(0x2_0000_0000, 8 * MIB, MemoryKind::AcpiReclaimable),
        ];
        let s = summarise(&map);
        assert_eq!(s.usable_bytes, (64 + 512) * MIB);
        assert_eq!(s.total_bytes, (64 + 16 + 512 + 8) * MIB);
        assert_eq!(s.largest_usable, Some((0x1_0000_0000, 512 * MIB)));
        assert_eq!(s.highest_address, 0x2_0000_0000 + 8 * MIB);
        assert_eq!(s.highest_ram, 0x2_0000_0000 + 8 * MIB);
    }

    #[test]
    fn a_device_aperture_does_not_stretch_the_ram_extent() {
        // The shape a q35 machine really produces: half a gigabyte of RAM, and
        // twelve gigabytes of reserved device space parked at 1012 GiB. Counting
        // the aperture as memory built a terabyte of linear map for it.
        let map = [
            MemoryRegion::new(0, 512 * MIB, MemoryKind::Usable),
            MemoryRegion::new(0xFD_0000_0000, 12 * 1024 * MIB, MemoryKind::Reserved),
        ];
        let s = summarise(&map);
        assert_eq!(s.highest_ram, 512 * MIB, "the aperture was counted as memory");
        // The unfiltered figure still reports it, because something has to.
        assert_eq!(s.highest_address, 0xFD_0000_0000 + 12 * 1024 * MIB);
    }

    #[test]
    fn every_kind_but_reserved_counts_as_ram() {
        // ACPI tables, NVS, the loader's own pages and even memory the firmware
        // called bad are all real, addressable RAM: the kernel has to be able to
        // reach them through the linear map. `Reserved` is the only kind that
        // might be an MMIO window rather than memory.
        for kind in [
            MemoryKind::Usable,
            MemoryKind::AcpiReclaimable,
            MemoryKind::AcpiNvs,
            MemoryKind::LoaderReclaimable,
            MemoryKind::BadMemory,
        ] {
            let s = summarise(&[MemoryRegion::new(0, 4 * MIB, kind)]);
            assert_eq!(s.highest_ram, 4 * MIB, "{kind:?} was treated as an aperture");
        }
        let s = summarise(&[MemoryRegion::new(0, 4 * MIB, MemoryKind::Reserved)]);
        assert_eq!(s.highest_ram, 0);
    }

    #[test]
    fn reclaimable_memory_is_not_usable_at_boot() {
        // The names promise a future; the allocator lives in the present.
        assert!(!MemoryKind::AcpiReclaimable.usable_at_boot());
        assert!(!MemoryKind::LoaderReclaimable.usable_at_boot());
        assert!(!MemoryKind::AcpiNvs.usable_at_boot());
        assert!(!MemoryKind::BadMemory.usable_at_boot());
        assert!(MemoryKind::Usable.usable_at_boot());
    }

    #[test]
    fn an_exclusion_in_the_middle_keeps_the_larger_half() {
        let map = [MemoryRegion::new(0, 100 * MIB, MemoryKind::Usable)];
        // Kernel at 10 MiB, 2 MiB long: 10 MiB below it, 88 above.
        let run = largest_free_run(&map, &[(10 * MIB, 2 * MIB)]);
        assert_eq!(run, Some((12 * MIB, 88 * MIB)));
    }

    #[test]
    fn an_exclusion_at_the_start_shortens_rather_than_splits() {
        let map = [MemoryRegion::new(0, 100 * MIB, MemoryKind::Usable)];
        assert_eq!(largest_free_run(&map, &[(0, 4 * MIB)]), Some((4 * MIB, 96 * MIB)));
    }

    #[test]
    fn a_disjoint_exclusion_changes_nothing() {
        let map = [MemoryRegion::new(64 * MIB, 64 * MIB, MemoryKind::Usable)];
        assert_eq!(
            largest_free_run(&map, &[(0, 1 * MIB), (256 * MIB, 8 * MIB)]),
            Some((64 * MIB, 64 * MIB)),
        );
    }

    #[test]
    fn an_exclusion_covering_a_region_removes_it_from_consideration() {
        let map = [
            MemoryRegion::new(0, 8 * MIB, MemoryKind::Usable),
            MemoryRegion::new(32 * MIB, 4 * MIB, MemoryKind::Usable),
        ];
        // Everything below 16 MiB is spoken for: only the second region survives.
        assert_eq!(largest_free_run(&map, &[(0, 16 * MIB)]), Some((32 * MIB, 4 * MIB)));
    }

    #[test]
    fn a_region_claiming_past_the_address_space_does_not_wrap() {
        let r = MemoryRegion::new(u64::MAX - 0xfff, 0x8000, MemoryKind::Usable);
        assert_eq!(r.end(), u64::MAX, "saturates instead of wrapping to zero");
        assert!(r.contains(u64::MAX - 1));
        let s = summarise(&[r]);
        assert_eq!(s.highest_address, u64::MAX);
    }

    #[test]
    fn no_usable_memory_is_none_not_zero() {
        let map = [MemoryRegion::new(0, 64 * MIB, MemoryKind::Reserved)];
        assert_eq!(summarise(&map).largest_usable, None);
        assert_eq!(largest_free_run(&map, &[]), None);
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn the_linear_map_and_the_kernel_image_do_not_overlap() {
        // Both live in the upper half, and the kernel image sits in the top 2 GiB
        // *inside* the range the linear map would otherwise want. The layout in
        // SPEC 3.1 stops the linear map short of it; this asserts the two
        // constants still say so.
        assert!(PHYS_MAP_BASE < KERNEL_VMA);
        assert_eq!(KERNEL_VMA - PHYS_MAP_BASE, 0x7FFF_8000_0000);
    }

    #[test]
    fn phys_to_virt_is_the_linear_map_and_saturates_instead_of_aliasing() {
        assert_eq!(phys_to_virt(0), PHYS_MAP_BASE);
        assert_eq!(phys_to_virt(0x8000_0000), PHYS_MAP_BASE + 0x8000_0000);
        // An address that cannot be reached must not wrap round to a low one and
        // quietly become a valid pointer to something else.
        assert_eq!(phys_to_virt(u64::MAX), u64::MAX);
    }

    #[test]
    fn gop_blue_first_is_the_drawing_crate_s_xrgb_and_the_names_invert() {
        let fmt = PixelFormat::Bgrx8888.to_framebuffer();
        assert_eq!(fmt, staros_framebuffer::PixelFormat::xrgb8888());
        // The check that actually matters: blue must encode into byte 0.
        assert_eq!(fmt.encode(0, 0, 0xFF), 0x0000_00FF);
        assert_eq!(fmt.encode(0xFF, 0, 0), 0x00FF_0000);
    }

    #[test]
    fn gop_red_first_is_the_drawing_crate_s_xbgr() {
        let fmt = PixelFormat::Rgbx8888.to_framebuffer();
        assert_eq!(fmt, staros_framebuffer::PixelFormat::xbgr8888());
        assert_eq!(fmt.encode(0xFF, 0, 0), 0x0000_00FF);
        assert_eq!(fmt.encode(0, 0, 0xFF), 0x00FF_0000);
    }

    #[test]
    fn a_framebuffer_descriptor_sizes_its_own_mapping_by_stride() {
        // 1366x768 is the classic mode where width*4 under-maps: the stride is
        // padded to 1376 pixels.
        let fb = Framebuffer::new(0x8000_0000, 1366, 768, 1376 * 4, PixelFormat::Bgrx8888);
        assert!(fb.is_sane());
        assert_eq!(fb.bytes(), 768 * 1376 * 4);
        assert!(fb.bytes() > u64::from(fb.width) * u64::from(fb.height) * 4);
    }
}
