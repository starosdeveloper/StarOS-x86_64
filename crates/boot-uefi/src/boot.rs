//! The loader's sequence, in the order `docs/SPEC.md` §2.2 specifies it.
//!
//! The ordering is not stylistic. Everything that needs boot services happens
//! first; the memory map is taken **last**, because every boot-services call
//! invalidates its key; and nothing between `GetMemoryMap` and
//! `ExitBootServices` may allocate, which is why the buffers those two steps use
//! are reserved before the loop starts.

use core::convert::Infallible;
use core::ffi::c_void;
use core::fmt::Write;

use staros_bootinfo::{BootInfo, Framebuffer, MemoryRegion, PixelFormat};
use staros_elf64::Elf;

use crate::alloc::{alloc_pages, check, pages_for, Error, PAGE_SIZE};
use crate::console::Console;
use crate::efi::{self, BootServices, GraphicsOutput, Handle, MemoryDescriptor, SystemTable};
use crate::fs::Volume;
use crate::memmap;
use crate::paging::{self, PageTables, Rights, KERNEL_VMA, PHYS_MAP_BASE};

/// One GiB, the granularity the identity and linear maps are rounded to.
const GIB: u64 = 1 << 30;

/// Map at least this much physical address space regardless of how much RAM is
/// installed. The local APIC (`0xFEE0_0000`), the I/O APIC, the HPET and the PCIe
/// ECAM window all sit just below 4 GiB on every PC, and the kernel must be able
/// to reach them through the linear map after ACPI names them — on a machine with
/// 2 GiB of RAM, sizing the map by RAM alone would leave every one unmapped.
///
/// This floor is also what makes it safe for [`memmap::highest_ram_address`] to
/// ignore device apertures: the ones needed early are all under it, and the ones
/// above it are for the kernel to map deliberately once it owns its tables.
const MIN_MAPPED: u64 = 4 * GIB;

/// Extra descriptors to budget for beyond what the first `GetMemoryMap` reports.
/// Allocating the kernel image and the page tables fragments the map, and the
/// buffer has to be big enough *after* that without allocating again.
const MAP_SLACK_DESCRIPTORS: usize = 32;

/// How many times to re-read the map when `ExitBootServices` rejects the key.
/// A handful, not unbounded: firmware that changes its map on every read will
/// never converge, and spinning forever hides that from anyone watching.
const EXIT_ATTEMPTS: usize = 8;

/// Run the whole loader. Returns only on failure.
///
/// # Errors
/// Any step's [`Error`], which the caller prints before halting.
///
/// # Safety
/// `image` and `st` must be the arguments `efi_main` received, unmodified.
pub unsafe fn run(
    image: Handle,
    st: &SystemTable,
    console: &mut Console,
) -> Result<Infallible, Error> {
    // SAFETY: boot services are live until this function calls ExitBootServices.
    let bs = unsafe { &*st.boot_services };

    // Firmware arms a five-minute watchdog before handing control to a boot
    // application. Reading a kernel off a slow USB stick can outlast it, and the
    // reset that follows is indistinguishable from a triple fault.
    // SAFETY: `bs` is live; a null data pointer with zero length is the
    // specified way to disarm.
    let _ = unsafe { (bs.set_watchdog_timer)(0, 0, 0, core::ptr::null_mut()) };

    // --- 1. ACPI RSDP -----------------------------------------------------
    // SAFETY: the configuration table array is valid while boot services are.
    let rsdp = unsafe { find_rsdp(st) };
    let _ = writeln!(console, "acpi: rsdp at {rsdp:#x}");
    if rsdp == 0 {
        // Not fatal here — the kernel will refuse for itself, and it can say so
        // on a console it owns. Failing now would trade a diagnosable boot for
        // an undiagnosable one.
        let _ = writeln!(console, "acpi: WARNING - no RSDP in the EFI configuration table");
    }

    // --- 2. Framebuffer ---------------------------------------------------
    // SAFETY: `bs` is live.
    let framebuffer = unsafe { locate_framebuffer(bs, console) };

    // --- 3. Files off the ESP --------------------------------------------
    // SAFETY: `image` and `st` are as `efi_main` received them.
    let volume = unsafe { Volume::open(image, st)? };
    // SAFETY: `bs` is live.
    let kernel_file = unsafe { volume.read_kernel(bs)? };
    // SAFETY: `bs` is live.
    let initrd = unsafe { volume.read_initrd(bs)? };
    let _ = writeln!(
        console,
        "esp: kernel {} KiB at {:#x}",
        kernel_file.len / 1024,
        kernel_file.phys
    );
    match initrd {
        Some(i) => {
            let _ = writeln!(console, "esp: initramfs {} KiB at {:#x}", i.len / 1024, i.phys);
        }
        None => {
            let _ = writeln!(console, "esp: no initramfs (optional)");
        }
    }

    // --- 4. Place the kernel image ---------------------------------------
    // SAFETY: the file is still mapped and owned by the loader.
    let image_bytes = unsafe { kernel_file.as_slice() };
    let elf = Elf::parse(image_bytes).map_err(|e| Error::own(e.as_str()))?;
    let (vbase, vsize) = elf.load_span().map_err(|e| Error::own(e.as_str()))?;
    if vbase != KERNEL_VMA {
        // The linker script and this loader must agree, and a mismatch produces a
        // kernel that runs at an address its own code does not believe in.
        return Err(Error::own("kernel image is not linked at the expected base"));
    }
    // SAFETY: `bs` is live.
    let kernel_phys = unsafe { alloc_pages(bs, "allocate kernel image", pages_for(vsize))? };

    // SAFETY: `bs` is live and the tree is not loaded into CR3 yet.
    let mut tables = unsafe { PageTables::new(bs)? };

    for seg in elf.segments() {
        let seg = seg.map_err(|e| Error::own(e.as_str()))?;
        if seg.rights.is_wx() {
            return Err(Error::own("kernel image contains a writable+executable segment"));
        }
        let dest = kernel_phys + (seg.vaddr - vbase);
        // SAFETY: `dest` lies inside the allocation (the span covers every
        // segment), the source is the file buffer, and the two do not overlap —
        // the file and the image are separate allocations.
        unsafe {
            core::ptr::copy_nonoverlapping(seg.file.as_ptr(), dest as *mut u8, seg.file.len());
        }
        // The tail beyond p_filesz is .bss; `alloc_pages` already zeroed the
        // whole span, so there is nothing to do but say why nothing is done.

        let rights = match (seg.rights.write, seg.rights.exec) {
            (_, true) => Rights::RX,
            (true, false) => Rights::RW,
            (false, false) => Rights::RO,
        };
        // SAFETY: `bs` is live; the tree is not in CR3 yet.
        unsafe {
            tables.map(bs, seg.vaddr, dest, seg.pages() * PAGE_SIZE, rights)?;
        }
    }
    let _ = writeln!(
        console,
        "kernel: {} KiB placed at {:#x}, mapped at {:#x}, entry {:#x}",
        vsize / 1024,
        kernel_phys,
        vbase,
        elf.entry()
    );

    // --- 5. Identity and linear maps -------------------------------------
    // A preliminary map, only to size the mapping. Its key is worthless —
    // allocating page tables below invalidates it — which is exactly why the
    // real one is taken later.
    // SAFETY: `bs` is live.
    let (probe_len, probe_desc) = unsafe { memory_map_size(bs)? };
    // SAFETY: `bs` is live.
    let probe_buf = unsafe { alloc_pages(bs, "allocate probe map", pages_for(probe_len as u64))? };
    // SAFETY: the buffer is `probe_len` bytes of loader-owned memory.
    let probe = unsafe {
        let mut size = pages_for(probe_len as u64) * PAGE_SIZE as usize;
        let mut key = 0usize;
        let mut desc_size = probe_desc;
        let mut desc_ver = 0u32;
        let status = (bs.get_memory_map)(
            &raw mut size,
            probe_buf as *mut MemoryDescriptor,
            &raw mut key,
            &raw mut desc_size,
            &raw mut desc_ver,
        );
        check("GetMemoryMap (probe)", status)?;
        (core::slice::from_raw_parts(probe_buf as *const u8, size), desc_size)
    };
    let mapped = memmap::highest_ram_address(probe.0, probe.1, GIB)
        .map_err(|_| Error::own("firmware reported an impossible descriptor size"))?
        .max(MIN_MAPPED);

    // Identity: read/write **and** executable. This is scaffolding with a
    // lifetime of one instruction — `mov cr3` takes effect on the next
    // instruction fetch, which must succeed at the address the loader is already
    // running at — and the kernel replaces it with its own tables in phase 1.4.
    // Making it non-writable would be tighter, but a mistake there faults with no
    // IDT installed, which is a silent reset rather than a message.
    // SAFETY: `bs` is live; the tree is not in CR3 yet.
    unsafe {
        tables.map(bs, 0, 0, mapped, Rights { write: true, exec: true })?;
        tables.map(bs, PHYS_MAP_BASE, 0, mapped, Rights::RW)?;
    }
    // The framebuffer is normally an aperture below 4 GiB and already inside the
    // maps above. Normally is not always: it is reported through GOP rather than
    // through the memory map, so nothing above ties it to RAM's extent, and a
    // machine that parks it higher would hand the kernel a console it cannot
    // touch. Map it where it is not already covered.
    let mut extra_fb = 0u64;
    if framebuffer.is_sane() {
        let base = framebuffer.phys & !(PAGE_SIZE - 1);
        let end = (framebuffer.phys + framebuffer.bytes()).next_multiple_of(PAGE_SIZE);
        if base >= mapped {
            extra_fb = end - base;
            // SAFETY: `bs` is live; the tree is not in CR3 yet.
            unsafe {
                tables.map(bs, base, base, extra_fb, Rights { write: true, exec: false })?;
                tables.map(bs, PHYS_MAP_BASE + base, base, extra_fb, Rights::RW)?;
            }
        }
    }

    let _ = writeln!(
        console,
        "paging: {} GiB identity + linear at {:#x} ({} pages), kernel W^X",
        mapped / GIB,
        PHYS_MAP_BASE,
        if tables.uses_gib_pages() { "1 GiB" } else { "2 MiB" },
    );
    if extra_fb != 0 {
        let _ = writeln!(
            console,
            "paging: framebuffer sits above RAM - mapped {} KiB separately",
            extra_fb / 1024
        );
    }

    // --- 6. Buffers for the hand-off, before the point of no allocation ---
    // SAFETY: `bs` is live.
    let info_phys = unsafe { alloc_pages(bs, "allocate boot info", 1)? };
    // SAFETY: `bs` is live.
    let (map_len, desc_size) = unsafe { memory_map_size(bs)? };
    let map_capacity = map_len + MAP_SLACK_DESCRIPTORS * desc_size;
    // SAFETY: `bs` is live.
    let map_buf = unsafe { alloc_pages(bs, "allocate memory map", pages_for(map_capacity as u64))? };
    let map_capacity = pages_for(map_capacity as u64) * PAGE_SIZE as usize;

    // One region per descriptor is the worst case; coalescing only ever reduces
    // it. Sizing it this way means the conversion cannot fail for want of room
    // after boot services are gone, when there is no way to allocate more.
    let region_capacity = map_capacity / desc_size;
    let regions_bytes = region_capacity * core::mem::size_of::<MemoryRegion>();
    // SAFETY: `bs` is live.
    let regions_phys = unsafe { alloc_pages(bs, "allocate region array", pages_for(regions_bytes as u64))? };

    // --- 7. Take the map and leave ---------------------------------------
    // No allocation past this point, on any path.
    let mut attempt = 0usize;
    let map_size = loop {
        attempt += 1;
        let mut size = map_capacity;
        let mut key = 0usize;
        let mut ds = desc_size;
        let mut dv = 0u32;
        // SAFETY: `map_buf` is `map_capacity` bytes of loader-owned memory.
        let status = unsafe {
            (bs.get_memory_map)(
                &raw mut size,
                map_buf as *mut MemoryDescriptor,
                &raw mut key,
                &raw mut ds,
                &raw mut dv,
            )
        };
        check("GetMemoryMap", status)?;

        // SAFETY: `image` is this image's handle and `key` is from the call above.
        let status = unsafe { (bs.exit_boot_services)(image, key) };
        if status == efi::SUCCESS {
            break size;
        }
        if status != efi::INVALID_PARAMETER || attempt >= EXIT_ATTEMPTS {
            return Err(Error::efi("ExitBootServices", status));
        }
        // A stale key is the expected outcome, not an error: firmware may have
        // changed the map while printing the line above. Re-read and retry,
        // without allocating — which is why every buffer was reserved earlier.
    };

    // Firmware is gone. From here the only output is serial, and the only code
    // running is this.
    console.firmware_is_gone();
    // SAFETY: ring 0; the specification leaves the interrupt flag's state to the
    // firmware here, and there is no IDT, so any interrupt would triple-fault.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };

    // --- 8. Build the hand-off structure ---------------------------------
    // SAFETY: the map buffer holds `map_size` bytes written by the firmware.
    let raw_map = unsafe { core::slice::from_raw_parts(map_buf as *const u8, map_size) };
    // SAFETY: the array was allocated with `region_capacity` elements and is
    // page-aligned, so it is aligned for `MemoryRegion`.
    let regions = unsafe {
        core::slice::from_raw_parts_mut(regions_phys as *mut MemoryRegion, region_capacity)
    };
    let count = memmap::convert(raw_map, desc_size, regions)
        .map_err(|_| Error::own("memory map did not fit the buffer reserved for it"))?;

    let info = BootInfo {
        magic: BootInfo::MAGIC,
        version: BootInfo::VERSION,
        memory_map_len: count as u32,
        memory_map: regions_phys,
        framebuffer,
        rsdp,
        initrd: initrd.map_or(0, |i| i.phys),
        initrd_len: initrd.map_or(0, |i| i.len),
        kernel_phys,
        kernel_len: vsize,
    };
    // SAFETY: `info_phys` is a whole page of loader-owned memory, which is
    // aligned for `BootInfo` and larger than it.
    unsafe { (info_phys as *mut BootInfo).write(info) };

    let _ = writeln!(
        console,
        "handoff: {count} regions, entry {:#x}, boot info at {:#x}",
        elf.entry(),
        info_phys
    );

    // --- 9. Switch tables and go -----------------------------------------
    // NXE first: with it clear, every NX bit in the tables just built is a
    // reserved-bit violation, and the fault would land with no IDT to take it.
    // SAFETY: ring 0, long mode.
    unsafe { paging::enable_no_execute() };

    // SAFETY: the tree maps the loader's current instruction pointer identically,
    // so execution survives the CR3 write; `entry` is the kernel's `_start`,
    // mapped executable above; `RDI` carries the boot info per SPEC §2.4. The
    // kernel establishes its own stack before touching memory.
    unsafe {
        core::arch::asm!(
            "mov cr3, {cr3}",
            "jmp {entry}",
            cr3 = in(reg) tables.cr3(),
            entry = in(reg) elf.entry(),
            in("rdi") info_phys,
            options(noreturn),
        );
    }
}

/// Find the ACPI RSDP in the EFI configuration table, preferring the 2.0 entry.
///
/// The 1.0 table is accepted as a fallback but is a real downgrade: its RSDP has
/// no XSDT, so every table address is 32-bit. Machines that offer only the 1.0
/// entry are old enough that this is consistent, not a trap.
///
/// # Safety
/// `st` must be the live system table.
unsafe fn find_rsdp(st: &SystemTable) -> u64 {
    // SAFETY: the array has `number_of_table_entries` entries while boot services
    // are alive.
    let entries = unsafe {
        core::slice::from_raw_parts(st.configuration_table, st.number_of_table_entries)
    };
    let mut fallback = 0u64;
    for e in entries {
        if e.guid == efi::ACPI2_GUID {
            return e.table as u64;
        }
        if e.guid == efi::ACPI1_GUID {
            fallback = e.table as u64;
        }
    }
    fallback
}

/// Ask GOP for the current mode and describe it, or report the absence.
///
/// A missing framebuffer is not fatal: a headless machine with a serial console
/// is a perfectly good target, and this kernel's first output channel works
/// either way.
///
/// # Safety
/// `bs` must be live boot services.
unsafe fn locate_framebuffer(bs: &BootServices, console: &mut Console) -> Framebuffer {
    const NONE: Framebuffer = Framebuffer::new(0, 0, 0, 0, PixelFormat::Bgrx8888);

    let mut iface: *mut c_void = core::ptr::null_mut();
    // SAFETY: `bs` is live; the out-param is a local.
    let status =
        unsafe { (bs.locate_protocol)(&efi::GOP_GUID, core::ptr::null_mut(), &raw mut iface) };
    if efi::is_error(status) || iface.is_null() {
        let _ = writeln!(console, "gop: no graphics output protocol - serial only");
        return NONE;
    }
    let gop = iface.cast::<GraphicsOutput>();
    // SAFETY: the firmware returned a valid GOP interface, whose `mode` and the
    // `info` it points at are valid for the life of the protocol.
    let (mode, info) = unsafe {
        let mode = (*gop).mode;
        if mode.is_null() || (*mode).info.is_null() {
            let _ = writeln!(console, "gop: protocol present but reports no mode");
            return NONE;
        }
        (&*mode, &*(*mode).info)
    };

    let format = match info.pixel_format {
        efi::gop_format::BGR => PixelFormat::Bgrx8888,
        efi::gop_format::RGB => PixelFormat::Rgbx8888,
        // A bit-mask or blt-only mode has no linear layout this console can
        // write. Reporting no framebuffer is honest; claiming one and drawing
        // noise is not.
        _ => {
            let _ = writeln!(console, "gop: unsupported pixel format - serial only");
            return NONE;
        }
    };

    // `pixels_per_scan_line` is in pixels; the stride is four times that. Firmware
    // pads rows, so this is not `width * 4`, and assuming it is shears the image.
    let fb = Framebuffer::new(
        mode.framebuffer_base,
        info.horizontal_resolution,
        info.vertical_resolution,
        info.pixels_per_scan_line * 4,
        format,
    );
    if !fb.is_sane() {
        let _ = writeln!(console, "gop: reported geometry is not self-consistent - ignoring");
        return NONE;
    }
    let _ = writeln!(
        console,
        "gop: {}x{} stride {} at {:#x}",
        fb.width, fb.height, fb.stride, fb.phys
    );
    fb
}

/// Ask how large the memory map currently is.
///
/// `GetMemoryMap` answers `EFI_BUFFER_TOO_SMALL` and fills in the size it wants;
/// that is the intended way to size the buffer, not an error.
///
/// # Safety
/// `bs` must be live boot services.
unsafe fn memory_map_size(bs: &BootServices) -> Result<(usize, usize), Error> {
    let mut size = 0usize;
    let mut key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_ver = 0u32;
    // SAFETY: `bs` is live; a null buffer with size 0 is the specified query form.
    let status = unsafe {
        (bs.get_memory_map)(
            &raw mut size,
            core::ptr::null_mut(),
            &raw mut key,
            &raw mut desc_size,
            &raw mut desc_ver,
        )
    };
    if status != efi::BUFFER_TOO_SMALL {
        check("GetMemoryMap (size query)", status)?;
    }
    if desc_size == 0 {
        return Err(Error::own("firmware reported a zero descriptor size"));
    }
    Ok((size, desc_size))
}
