//! Turning the firmware's memory map into the kernel's.
//!
//! Two things go wrong here on real machines, and both are silent:
//!
//! 1. **Striding by the wrong size.** `GetMemoryMap` returns its own
//!    `descriptor_size`, and firmware is explicitly permitted to make it larger
//!    than `sizeof(EFI_MEMORY_DESCRIPTOR)` — some do, by eight bytes. Walking the
//!    buffer with `size_of` instead reads each entry a little further off than
//!    the last, and the resulting map looks *plausible* rather than wrong.
//! 2. **Trusting the type names.** `EfiBootServicesData` is free after
//!    `ExitBootServices` in principle, and firmware that keeps using it is common
//!    enough that reclaiming it is a coin flip. This module classifies it as
//!    reserved, and the loss is a few MiB.
//!
//! So the walk lives here, as a pure function over a byte slice, with tests that
//! feed it an oversized descriptor stride and a fragmented map — because the one
//! place this code runs for real is a few instructions before the last chance to
//! print anything.

use staros_bootinfo::{MemoryKind, MemoryRegion};

use crate::efi::{memory_type, MemoryDescriptor};

/// Bytes per page in a UEFI memory descriptor's `pages` field. Fixed by the
/// specification, independent of the page size the CPU is configured for.
pub const EFI_PAGE_SIZE: u64 = 4096;

/// Why a conversion failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConvertError {
    /// `descriptor_size` is smaller than the structure it describes, so the
    /// firmware's own stride would read each entry into the next.
    BadDescriptorSize,
    /// The output slice cannot hold the regions. Carries how many are needed, so
    /// the caller can report the shortfall rather than guess at a bigger buffer.
    TooManyRegions(usize),
}

/// What a UEFI memory type means to the kernel.
///
/// Conservative by construction: only `EfiConventionalMemory` becomes
/// [`MemoryKind::Usable`]. Everything unrecognised is [`MemoryKind::Reserved`],
/// which costs memory and never costs correctness — the opposite trade is a
/// frame allocator handing out the firmware's own data structures.
#[must_use]
pub const fn classify(ty: u32) -> MemoryKind {
    match ty {
        memory_type::CONVENTIONAL => MemoryKind::Usable,
        memory_type::ACPI_RECLAIM => MemoryKind::AcpiReclaimable,
        memory_type::ACPI_NVS => MemoryKind::AcpiNvs,
        memory_type::UNUSABLE => MemoryKind::BadMemory,
        // The loader's own image and everything it allocated for the kernel: the
        // kernel image, the page tables, the boot info, this very map.
        memory_type::LOADER_CODE | memory_type::LOADER_DATA => MemoryKind::LoaderReclaimable,
        // Boot-services memory is *nominally* free once boot services are gone.
        // Left reserved on purpose; see the module comment.
        memory_type::BOOT_SERVICES_CODE | memory_type::BOOT_SERVICES_DATA => MemoryKind::Reserved,
        memory_type::PERSISTENT => MemoryKind::Reserved,
        _ => MemoryKind::Reserved,
    }
}

/// Walk a raw UEFI memory map and write the kernel's view of it into `out`.
///
/// `descriptor_size` comes from `GetMemoryMap` and is the **only** correct
/// stride. Adjacent entries of the same kind are coalesced: a firmware map of 90
/// descriptors routinely collapses to a dozen regions, and every one removed is
/// one the kernel does not have to carry.
///
/// Returns how many regions were written.
///
/// # Errors
/// [`ConvertError::BadDescriptorSize`] for a stride that cannot hold a
/// descriptor, [`ConvertError::TooManyRegions`] if `out` is too small.
pub fn convert(
    map: &[u8],
    descriptor_size: usize,
    out: &mut [MemoryRegion],
) -> Result<usize, ConvertError> {
    if descriptor_size < core::mem::size_of::<MemoryDescriptor>() {
        return Err(ConvertError::BadDescriptorSize);
    }

    let mut n = 0usize;
    let mut offset = 0usize;
    // A trailing partial descriptor is ignored rather than read: `map` is sized
    // by the firmware and may legitimately have slack past the last entry.
    while offset + descriptor_size <= map.len() {
        let raw = &map[offset..offset + descriptor_size];
        offset += descriptor_size;

        // Read the fields by offset instead of transmuting: the buffer's
        // alignment is the firmware's business, and a misaligned load of a
        // `#[repr(C)]` struct is undefined behaviour even when it happens to work.
        let ty = u32::from_le_bytes(raw[0..4].try_into().expect("4 bytes"));
        let phys = u64::from_le_bytes(raw[8..16].try_into().expect("8 bytes"));
        let pages = u64::from_le_bytes(raw[24..32].try_into().expect("8 bytes"));

        let len = pages.saturating_mul(EFI_PAGE_SIZE);
        if len == 0 {
            continue;
        }
        let kind = classify(ty);

        // Coalesce with the previous region when it is the same kind and ends
        // exactly where this one starts.
        if n > 0 {
            let prev = &mut out[n - 1];
            if prev.kind == kind && prev.end() == phys {
                prev.len = prev.len.saturating_add(len);
                continue;
            }
        }
        if n == out.len() {
            // Count what is left so the caller learns the real requirement, not
            // just that it was short.
            let remaining = (map.len() - offset) / descriptor_size;
            return Err(ConvertError::TooManyRegions(n + 1 + remaining));
        }
        out[n] = MemoryRegion::new(phys, len, kind);
        n += 1;
    }
    Ok(n)
}

/// The highest physical address any descriptor reaches, rounded up to `align`.
///
/// Used to size the identity and linear maps. Every entry counts, not just the
/// usable ones: MMIO apertures reported by firmware must be reachable through the
/// linear map, or the kernel cannot touch a device it discovers through ACPI.
///
/// # Errors
/// [`ConvertError::BadDescriptorSize`] for an impossible stride.
pub fn highest_address(map: &[u8], descriptor_size: usize, align: u64) -> Result<u64, ConvertError> {
    if descriptor_size < core::mem::size_of::<MemoryDescriptor>() {
        return Err(ConvertError::BadDescriptorSize);
    }
    let mut hi = 0u64;
    let mut offset = 0usize;
    while offset + descriptor_size <= map.len() {
        let raw = &map[offset..offset + descriptor_size];
        offset += descriptor_size;
        let phys = u64::from_le_bytes(raw[8..16].try_into().expect("8 bytes"));
        let pages = u64::from_le_bytes(raw[24..32].try_into().expect("8 bytes"));
        hi = hi.max(phys.saturating_add(pages.saturating_mul(EFI_PAGE_SIZE)));
    }
    // Saturating, not `next_multiple_of`: a descriptor that claims the very top
    // of the address space would otherwise overflow the rounding and report a
    // *small* number, under-sizing the linear map on exactly the machine whose
    // firmware is already lying about its memory.
    Ok(hi.checked_next_multiple_of(align).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode one descriptor with a caller-chosen stride, so tests can reproduce
    /// the padded descriptors real firmware emits.
    fn desc(ty: u32, phys: u64, pages: u64, stride: usize) -> Vec<u8> {
        let mut d = vec![0u8; stride];
        d[0..4].copy_from_slice(&ty.to_le_bytes());
        d[8..16].copy_from_slice(&phys.to_le_bytes());
        d[16..24].copy_from_slice(&0u64.to_le_bytes()); // virt_start
        d[24..32].copy_from_slice(&pages.to_le_bytes());
        d[32..40].copy_from_slice(&0xFu64.to_le_bytes()); // attribute
        d
    }

    fn map_of(entries: &[(u32, u64, u64)], stride: usize) -> Vec<u8> {
        entries.iter().flat_map(|&(t, p, n)| desc(t, p, n, stride)).collect()
    }

    const NATIVE: usize = core::mem::size_of::<MemoryDescriptor>();

    #[test]
    fn a_descriptor_is_forty_bytes_and_the_field_offsets_match() {
        // The conversion reads by offset; if the struct ever changes shape, this
        // is the test that says so before the offsets quietly disagree with it.
        assert_eq!(NATIVE, 40);
        assert_eq!(core::mem::offset_of!(MemoryDescriptor, ty), 0);
        assert_eq!(core::mem::offset_of!(MemoryDescriptor, phys_start), 8);
        assert_eq!(core::mem::offset_of!(MemoryDescriptor, pages), 24);
    }

    #[test]
    fn converts_a_simple_map() {
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 16),
                (memory_type::ACPI_RECLAIM, 0x10_000, 2),
            ],
            NATIVE,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 8];
        let n = convert(&map, NATIVE, &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(out[0], MemoryRegion::new(0, 16 * 4096, MemoryKind::Usable));
        assert_eq!(out[1], MemoryRegion::new(0x10_000, 8192, MemoryKind::AcpiReclaimable));
    }

    #[test]
    fn an_oversized_descriptor_stride_is_honoured() {
        // The failure this exists for: firmware reporting descriptor_size = 48.
        // Walking with size_of would read entry 1 eight bytes early, producing a
        // map that is wrong but not obviously so.
        let stride = 48;
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 1),
                (memory_type::ACPI_NVS, 0x8_0000, 1),
            ],
            stride,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 8];
        let n = convert(&map, stride, &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(out[1].start, 0x8_0000);
        assert_eq!(out[1].kind, MemoryKind::AcpiNvs);

        // And the same buffer read with the wrong stride does *not* produce this
        // — which is the whole point of taking the size from the firmware.
        let mut wrong = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 8];
        let n_wrong = convert(&map, NATIVE, &mut wrong).unwrap();
        assert_ne!(&wrong[..n_wrong], &out[..n]);
    }

    #[test]
    fn adjacent_regions_of_the_same_kind_coalesce() {
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 1),
                (memory_type::CONVENTIONAL, 0x1000, 1),
                (memory_type::CONVENTIONAL, 0x2000, 2),
            ],
            NATIVE,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 8];
        assert_eq!(convert(&map, NATIVE, &mut out).unwrap(), 1);
        assert_eq!(out[0], MemoryRegion::new(0, 4 * 4096, MemoryKind::Usable));
    }

    #[test]
    fn boot_services_memory_coalesces_with_reserved_because_both_are_reserved() {
        // Not an accident worth hiding: the classification is what makes these
        // one region, and the kernel is meant to see one region.
        let map = map_of(
            &[
                (memory_type::BOOT_SERVICES_DATA, 0x0, 1),
                (0xDEAD_BEEF, 0x1000, 1),
            ],
            NATIVE,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 4];
        assert_eq!(convert(&map, NATIVE, &mut out).unwrap(), 1);
        assert_eq!(out[0].len, 8192);
        assert_eq!(out[0].kind, MemoryKind::Reserved);
    }

    #[test]
    fn a_gap_prevents_coalescing_even_for_the_same_kind() {
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 1),
                (memory_type::CONVENTIONAL, 0x2000, 1),
            ],
            NATIVE,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 4];
        assert_eq!(convert(&map, NATIVE, &mut out).unwrap(), 2);
    }

    #[test]
    fn zero_page_entries_are_dropped_and_do_not_break_coalescing() {
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 1),
                (memory_type::ACPI_NVS, 0x1000, 0),
                (memory_type::CONVENTIONAL, 0x1000, 1),
            ],
            NATIVE,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 4];
        assert_eq!(convert(&map, NATIVE, &mut out).unwrap(), 1);
        assert_eq!(out[0].len, 8192);
    }

    #[test]
    fn a_full_output_slice_reports_how_many_regions_were_needed() {
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 1),
                (memory_type::ACPI_NVS, 0x1000, 1),
                (memory_type::CONVENTIONAL, 0x2000, 1),
                (memory_type::ACPI_NVS, 0x3000, 1),
            ],
            NATIVE,
        );
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 2];
        assert_eq!(convert(&map, NATIVE, &mut out), Err(ConvertError::TooManyRegions(4)));
    }

    #[test]
    fn an_impossible_descriptor_size_is_rejected_before_any_read() {
        let map = vec![0u8; 128];
        assert_eq!(convert(&map, 8, &mut []), Err(ConvertError::BadDescriptorSize));
        assert_eq!(highest_address(&map, 8, 4096), Err(ConvertError::BadDescriptorSize));
    }

    #[test]
    fn a_trailing_partial_descriptor_is_ignored() {
        let mut map = map_of(&[(memory_type::CONVENTIONAL, 0x0, 1)], NATIVE);
        map.extend_from_slice(&[0xAB; 17]);
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 4];
        assert_eq!(convert(&map, NATIVE, &mut out).unwrap(), 1);
    }

    #[test]
    fn an_empty_map_converts_to_nothing_rather_than_failing() {
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 4];
        assert_eq!(convert(&[], NATIVE, &mut out).unwrap(), 0);
        assert_eq!(highest_address(&[], NATIVE, 4096).unwrap(), 0);
    }

    #[test]
    fn highest_address_covers_mmio_above_ram_and_rounds_up() {
        let map = map_of(
            &[
                (memory_type::CONVENTIONAL, 0x0, 0x8_0000),   // 2 GiB of RAM
                (0xB, 0xFEE0_0000, 1),                        // local APIC MMIO
            ],
            NATIVE,
        );
        const GIB: u64 = 1 << 30;
        // Rounded to the next GiB boundary above 0xFEE01000.
        assert_eq!(highest_address(&map, NATIVE, GIB).unwrap(), 4 * GIB);
    }

    #[test]
    fn a_descriptor_claiming_the_end_of_the_address_space_saturates() {
        let map = map_of(&[(memory_type::CONVENTIONAL, u64::MAX - 4095, u64::MAX)], NATIVE);
        // Must not wrap to a small number, which would under-size the linear map.
        assert_eq!(highest_address(&map, NATIVE, 4096).unwrap(), u64::MAX);
        let mut out = [MemoryRegion::new(0, 0, MemoryKind::Reserved); 4];
        assert_eq!(convert(&map, NATIVE, &mut out).unwrap(), 1);
        assert_eq!(out[0].end(), u64::MAX);
    }

    #[test]
    fn classification_is_conservative_for_unknown_types() {
        for ty in [0u32, 5, 6, 11, 12, 13, 14, 15, 0x7000_0000, u32::MAX] {
            assert_eq!(classify(ty), MemoryKind::Reserved, "type {ty} must not be usable");
        }
        assert_eq!(classify(memory_type::CONVENTIONAL), MemoryKind::Usable);
        assert!(classify(memory_type::CONVENTIONAL).usable_at_boot());
        assert!(!classify(memory_type::ACPI_RECLAIM).usable_at_boot());
        assert!(!classify(memory_type::LOADER_DATA).usable_at_boot());
    }
}
