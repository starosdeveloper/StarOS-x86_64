//! Raw UEFI bindings — only the parts this loader calls.
//!
//! Hand-written rather than pulled from a crate, for the same reason the rest of
//! this workspace has no dependencies: the whole surface is fourteen function
//! pointers and six structs, and every one of them is a **layout** contract with
//! firmware. A layout contract is precisely the thing worth reading in the source
//! you build, next to the spec section it comes from, rather than trusting a
//! version resolver with.
//!
//! Field order in [`BootServices`] is the ABI. Entries this loader never calls
//! are declared as opaque `usize` slots so they still occupy their position —
//! deleting one would silently shift every function after it, and the first
//! symptom would be the firmware jumping into the middle of another routine.
//!
//! References are to UEFI Specification 2.10.

use core::ffi::c_void;

/// `EFI_STATUS`. High bit set means error.
pub type Status = usize;
/// `EFI_HANDLE`.
pub type Handle = *mut c_void;

/// The error bit of an `EFI_STATUS` on a 64-bit machine.
const ERROR_BIT: Status = 1 << (usize::BITS - 1);

/// `EFI_SUCCESS`.
pub const SUCCESS: Status = 0;
/// `EFI_INVALID_PARAMETER` — returned by `ExitBootServices` when the map key is
/// stale, which is the one error this loader treats as "try again".
pub const INVALID_PARAMETER: Status = ERROR_BIT | 2;
/// `EFI_BUFFER_TOO_SMALL` — how `GetMemoryMap` reports the size it needs.
pub const BUFFER_TOO_SMALL: Status = ERROR_BIT | 5;

/// Whether a status is an error.
#[must_use]
pub const fn is_error(status: Status) -> bool {
    status & ERROR_BIT != 0
}

/// `EFI_GUID`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Guid {
    /// First 32 bits, little-endian in memory.
    pub a: u32,
    /// Next 16 bits.
    pub b: u16,
    /// Next 16 bits.
    pub c: u16,
    /// The final eight bytes, in byte order.
    pub d: [u8; 8],
}

/// `EFI_ACPI_20_TABLE_GUID` — the RSDP for ACPI 2.0 and later (an XSDT-bearing
/// RSDP, which is what this kernel wants).
pub const ACPI2_GUID: Guid = Guid {
    a: 0x8868_e871,
    b: 0xe4f1,
    c: 0x11d3,
    d: [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
};
/// `ACPI_TABLE_GUID` — the ACPI 1.0 RSDP. Accepted only if the 2.0 one is
/// absent, and it will cost the machine its XSDT.
pub const ACPI1_GUID: Guid = Guid {
    a: 0xeb9d_2d30,
    b: 0x2d88,
    c: 0x11d3,
    d: [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
};
/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID`.
pub const GOP_GUID: Guid = Guid {
    a: 0x9042_a9de,
    b: 0x23dc,
    c: 0x4a38,
    d: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};
/// `EFI_LOADED_IMAGE_PROTOCOL_GUID` — how the loader finds the volume it was
/// itself loaded from, so the kernel is read from *that* ESP and not a guess.
pub const LOADED_IMAGE_GUID: Guid = Guid {
    a: 0x5b1b_31a1,
    b: 0x9562,
    c: 0x11d2,
    d: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID`.
pub const SIMPLE_FS_GUID: Guid = Guid {
    a: 0x964e_5b22,
    b: 0x6459,
    c: 0x11d2,
    d: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
/// `EFI_FILE_INFO_ID` — the `GetInfo` selector that carries the file size.
pub const FILE_INFO_GUID: Guid = Guid {
    a: 0x0957_6e92,
    b: 0x6d3f,
    c: 0x11d2,
    d: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

/// `EFI_TABLE_HEADER`.
#[derive(Debug)]
#[repr(C)]
pub struct TableHeader {
    /// Identifies which table this is.
    pub signature: u64,
    /// Revision of the table layout.
    pub revision: u32,
    /// Size of the whole table in bytes.
    pub header_size: u32,
    /// CRC32 of the table with this field zeroed.
    pub crc32: u32,
    /// Reserved, zero.
    pub reserved: u32,
}

/// `EFI_MEMORY_TYPE` values this loader distinguishes. The firmware defines
/// more; anything not listed is treated as reserved, which is the safe default
/// for memory whose purpose we do not recognise.
pub mod memory_type {
    /// `EfiLoaderData` — what the loader allocates for the kernel and its
    /// hand-off structures.
    pub const LOADER_DATA: u32 = 2;
    /// `EfiBootServicesCode`. Free after `ExitBootServices`, but this loader does
    /// not claim it: firmware is known to keep executing from it in
    /// runtime-services corner cases, and a few MiB is not worth that argument.
    pub const BOOT_SERVICES_CODE: u32 = 3;
    /// `EfiBootServicesData`. Same reasoning.
    pub const BOOT_SERVICES_DATA: u32 = 4;
    /// `EfiConventionalMemory` — plainly free RAM.
    pub const CONVENTIONAL: u32 = 7;
    /// `EfiUnusableMemory` — present but reported bad.
    pub const UNUSABLE: u32 = 8;
    /// `EfiACPIReclaimMemory` — holds the ACPI tables.
    pub const ACPI_RECLAIM: u32 = 9;
    /// `EfiACPIMemoryNVS` — must survive sleep states; never usable.
    pub const ACPI_NVS: u32 = 10;
    /// `EfiLoaderCode` — the loader's own image.
    pub const LOADER_CODE: u32 = 1;
    /// `EfiPersistentMemory` — byte-addressable non-volatile memory. Present, but
    /// not general-purpose RAM.
    pub const PERSISTENT: u32 = 14;
}

/// `EFI_ALLOCATE_TYPE::AllocateAnyPages`.
pub const ALLOCATE_ANY_PAGES: u32 = 0;

/// `EFI_MEMORY_DESCRIPTOR`.
///
/// Never stride an array of these by `size_of::<MemoryDescriptor>()`.
/// `GetMemoryMap` reports its own `descriptor_size`, which firmware is explicitly
/// allowed to make larger, and the difference between the two is the single most
/// common way a loader reads a memory map into garbage.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryDescriptor {
    /// One of [`memory_type`].
    pub ty: u32,
    /// Padding to align `phys_start`.
    pub pad: u32,
    /// Physical base of the range.
    pub phys_start: u64,
    /// Virtual base, meaningful only after `SetVirtualAddressMap`.
    pub virt_start: u64,
    /// Length in 4 KiB pages.
    pub pages: u64,
    /// `EFI_MEMORY_*` capability bits.
    pub attribute: u64,
}

/// `EFI_BOOT_SERVICES`.
///
/// Order is the ABI; see the module comment. Unused entries are `usize`.
#[repr(C)]
pub struct BootServices {
    /// Table header.
    pub hdr: TableHeader,

    /// `RaiseTPL`.
    pub raise_tpl: usize,
    /// `RestoreTPL`.
    pub restore_tpl: usize,

    /// `AllocatePages(type, memory_type, pages, &mut physical_address)`.
    pub allocate_pages:
        unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    /// `FreePages`.
    pub free_pages: unsafe extern "efiapi" fn(u64, usize) -> Status,
    /// `GetMemoryMap(&mut size, buffer, &mut key, &mut desc_size, &mut desc_ver)`.
    pub get_memory_map: unsafe extern "efiapi" fn(
        *mut usize,
        *mut MemoryDescriptor,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> Status,
    /// `AllocatePool`.
    pub allocate_pool:
        unsafe extern "efiapi" fn(u32, usize, *mut *mut u8) -> Status,
    /// `FreePool`.
    pub free_pool: unsafe extern "efiapi" fn(*mut u8) -> Status,

    /// `CreateEvent`.
    pub create_event: usize,
    /// `SetTimer`.
    pub set_timer: usize,
    /// `WaitForEvent`.
    pub wait_for_event: usize,
    /// `SignalEvent`.
    pub signal_event: usize,
    /// `CloseEvent`.
    pub close_event: usize,
    /// `CheckEvent`.
    pub check_event: usize,

    /// `InstallProtocolInterface`.
    pub install_protocol_interface: usize,
    /// `ReinstallProtocolInterface`.
    pub reinstall_protocol_interface: usize,
    /// `UninstallProtocolInterface`.
    pub uninstall_protocol_interface: usize,
    /// `HandleProtocol(handle, &guid, &mut interface)`.
    pub handle_protocol:
        unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    /// Reserved slot, present since EFI 1.02.
    pub reserved: usize,
    /// `RegisterProtocolNotify`.
    pub register_protocol_notify: usize,
    /// `LocateHandle`.
    pub locate_handle: usize,
    /// `LocateDevicePath`.
    pub locate_device_path: usize,
    /// `InstallConfigurationTable`.
    pub install_configuration_table: usize,

    /// `LoadImage`.
    pub load_image: usize,
    /// `StartImage`.
    pub start_image: usize,
    /// `Exit`.
    pub exit: usize,
    /// `UnloadImage`.
    pub unload_image: usize,
    /// `ExitBootServices(image_handle, map_key)`.
    pub exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,

    /// `GetNextMonotonicCount`.
    pub get_next_monotonic_count: usize,
    /// `Stall(microseconds)`.
    pub stall: unsafe extern "efiapi" fn(usize) -> Status,
    /// `SetWatchdogTimer(timeout, code, data_size, data)`. Disarmed early: the
    /// firmware's five-minute watchdog will reset the machine mid-load otherwise,
    /// and the reset looks exactly like a triple fault.
    pub set_watchdog_timer:
        unsafe extern "efiapi" fn(usize, u64, usize, *mut u16) -> Status,

    /// `ConnectController`.
    pub connect_controller: usize,
    /// `DisconnectController`.
    pub disconnect_controller: usize,

    /// `OpenProtocol`.
    pub open_protocol: usize,
    /// `CloseProtocol`.
    pub close_protocol: usize,
    /// `OpenProtocolInformation`.
    pub open_protocol_information: usize,

    /// `ProtocolsPerHandle`.
    pub protocols_per_handle: usize,
    /// `LocateHandleBuffer`.
    pub locate_handle_buffer: usize,
    /// `LocateProtocol(&guid, registration, &mut interface)`.
    pub locate_protocol:
        unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
    /// `InstallMultipleProtocolInterfaces`.
    pub install_multiple_protocol_interfaces: usize,
    /// `UninstallMultipleProtocolInterfaces`.
    pub uninstall_multiple_protocol_interfaces: usize,

    /// `CalculateCrc32`.
    pub calculate_crc32: usize,

    /// `CopyMem`.
    pub copy_mem: usize,
    /// `SetMem`.
    pub set_mem: usize,
    /// `CreateEventEx`.
    pub create_event_ex: usize,
}

/// `EFI_CONFIGURATION_TABLE` — a `(GUID, pointer)` pair. The ACPI RSDP is found
/// here and nowhere else on a UEFI machine; scanning the BIOS area for `RSD PTR`
/// is the legacy path and is not guaranteed to work.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ConfigurationTable {
    /// Which table this is.
    pub guid: Guid,
    /// Physical address of the table.
    pub table: *mut c_void,
}

/// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`, truncated after the calls used.
#[repr(C)]
pub struct SimpleTextOutput {
    /// `Reset(this, extended_verification)`.
    pub reset: unsafe extern "efiapi" fn(*mut SimpleTextOutput, bool) -> Status,
    /// `OutputString(this, null-terminated UCS-2)`.
    pub output_string:
        unsafe extern "efiapi" fn(*mut SimpleTextOutput, *const u16) -> Status,
    /// `TestString`.
    pub test_string: usize,
    /// `QueryMode`.
    pub query_mode: usize,
    /// `SetMode`.
    pub set_mode: usize,
    /// `SetAttribute`.
    pub set_attribute: usize,
    /// `ClearScreen(this)`.
    pub clear_screen: unsafe extern "efiapi" fn(*mut SimpleTextOutput) -> Status,
}

/// `EFI_SYSTEM_TABLE`.
#[repr(C)]
pub struct SystemTable {
    /// Table header.
    pub hdr: TableHeader,
    /// Vendor string, UCS-2.
    pub firmware_vendor: *const u16,
    /// Vendor-defined revision.
    pub firmware_revision: u32,
    /// Handle of the active console input device.
    pub console_in_handle: Handle,
    /// `EFI_SIMPLE_TEXT_INPUT_PROTOCOL`.
    pub con_in: *mut c_void,
    /// Handle of the active console output device.
    pub console_out_handle: Handle,
    /// The firmware console this loader prints to before it leaves.
    pub con_out: *mut SimpleTextOutput,
    /// Handle of the standard error device.
    pub standard_error_handle: Handle,
    /// Standard error console.
    pub std_err: *mut SimpleTextOutput,
    /// `EFI_RUNTIME_SERVICES`. Survives `ExitBootServices`; unused here, because
    /// using it would mean calling firmware code after the kernel owns paging.
    pub runtime_services: *mut c_void,
    /// `EFI_BOOT_SERVICES`.
    pub boot_services: *mut BootServices,
    /// Number of entries in [`Self::configuration_table`].
    pub number_of_table_entries: usize,
    /// Array of vendor tables — where the ACPI RSDP lives.
    pub configuration_table: *const ConfigurationTable,
}

/// `EFI_GRAPHICS_OUTPUT_MODE_INFORMATION`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GopModeInfo {
    /// Structure version.
    pub version: u32,
    /// Visible width in pixels.
    pub horizontal_resolution: u32,
    /// Visible height in pixels.
    pub vertical_resolution: u32,
    /// One of [`gop_format`].
    pub pixel_format: u32,
    /// Channel masks, meaningful only for `PIXEL_BIT_MASK`.
    pub pixel_information: [u32; 4],
    /// **Pixels** per scan line, not bytes: the stride is this times four. Larger
    /// than the visible width on most machines, and assuming otherwise shears the
    /// image.
    pub pixels_per_scan_line: u32,
}

/// `EFI_GRAPHICS_PIXEL_FORMAT` values.
pub mod gop_format {
    /// `PixelRedGreenBlueReserved8BitPerColor` — red in the lowest byte.
    pub const RGB: u32 = 0;
    /// `PixelBlueGreenRedReserved8BitPerColor` — blue in the lowest byte. What
    /// nearly every PC reports.
    pub const BGR: u32 = 1;
    /// `PixelBitMask` — arbitrary channel masks. Not supported: the console would
    /// need a general shifter, and no machine this targets reports it.
    pub const BIT_MASK: u32 = 2;
    /// `PixelBltOnly` — no linear framebuffer at all. The display is only
    /// reachable through boot services, which are about to stop existing.
    pub const BLT_ONLY: u32 = 3;
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GopMode {
    /// Number of modes the device supports.
    pub max_mode: u32,
    /// The mode currently set.
    pub mode: u32,
    /// Description of the current mode.
    pub info: *const GopModeInfo,
    /// Size of the structure `info` points at.
    pub size_of_info: usize,
    /// Physical base of the linear framebuffer.
    pub framebuffer_base: u64,
    /// Its size in bytes.
    pub framebuffer_size: usize,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
#[repr(C)]
pub struct GraphicsOutput {
    /// `QueryMode`.
    pub query_mode: usize,
    /// `SetMode`.
    pub set_mode: usize,
    /// `Blt`.
    pub blt: usize,
    /// The current mode, including the framebuffer address.
    pub mode: *const GopMode,
}

/// `EFI_LOADED_IMAGE_PROTOCOL`, truncated after `device_handle`.
#[repr(C)]
pub struct LoadedImage {
    /// Protocol revision.
    pub revision: u32,
    /// Handle of the image that loaded this one.
    pub parent_handle: Handle,
    /// The system table passed to this image.
    pub system_table: *const SystemTable,
    /// The device this image was loaded from — the ESP to read the kernel from.
    pub device_handle: Handle,
    /// Remainder of the structure, not used here.
    pub file_path: *mut c_void,
}

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`.
#[repr(C)]
pub struct SimpleFileSystem {
    /// Protocol revision.
    pub revision: u64,
    /// `OpenVolume(this, &mut root)`.
    pub open_volume:
        unsafe extern "efiapi" fn(*mut SimpleFileSystem, *mut *mut File) -> Status,
}

/// `EFI_FILE_MODE_READ`.
pub const FILE_MODE_READ: u64 = 1;

/// `EFI_FILE_PROTOCOL`.
#[repr(C)]
pub struct File {
    /// Protocol revision.
    pub revision: u64,
    /// `Open(this, &mut new, name, open_mode, attributes)`.
    pub open: unsafe extern "efiapi" fn(
        *mut File,
        *mut *mut File,
        *const u16,
        u64,
        u64,
    ) -> Status,
    /// `Close(this)`.
    pub close: unsafe extern "efiapi" fn(*mut File) -> Status,
    /// `Delete`.
    pub delete: usize,
    /// `Read(this, &mut size, buffer)`.
    pub read: unsafe extern "efiapi" fn(*mut File, *mut usize, *mut u8) -> Status,
    /// `Write`.
    pub write: usize,
    /// `GetPosition`.
    pub get_position: usize,
    /// `SetPosition`.
    pub set_position: usize,
    /// `GetInfo(this, &info_guid, &mut size, buffer)`.
    pub get_info: unsafe extern "efiapi" fn(
        *mut File,
        *const Guid,
        *mut usize,
        *mut u8,
    ) -> Status,
    /// `SetInfo`.
    pub set_info: usize,
    /// `Flush`.
    pub flush: usize,
}

/// Byte offset of `FileSize` inside `EFI_FILE_INFO`: after the 8-byte `Size`.
pub const FILE_INFO_SIZE_OFFSET: usize = 8;
