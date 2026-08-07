//! Reading the kernel and the initramfs off the ESP.
//!
//! The volume is not searched for: it is the one this loader was **itself**
//! loaded from, obtained through `EFI_LOADED_IMAGE_PROTOCOL`. On a machine with
//! two ESPs — a dual-boot disk, or a USB stick plugged into a system that already
//! has one — searching would find the wrong one about half the time, and the
//! symptom would be a kernel from the previous build with no indication why.
//!
//! Files land in page-aligned `EfiLoaderData`, so the kernel image can be parsed
//! in place and the initramfs handed to the kernel by physical address without a
//! second copy.

use core::ffi::c_void;

use crate::alloc::{alloc_pages, check, pages_for, Error, PAGE_SIZE};
use crate::efi::{
    self, BootServices, File, Guid, Handle, LoadedImage, SimpleFileSystem, SystemTable,
};

/// The directory on the ESP that holds this OS's files.
///
/// `\staros\` rather than the root: an ESP is shared with other operating systems
/// and with firmware update payloads, and a file called `kernel` in the root of
/// one is a collision waiting to happen.
const KERNEL_PATH: [u16; 15] = ucs2(b"\\staros\\kernel");
/// Optional initramfs, same directory.
const INITRD_PATH: [u16; 18] = ucs2(b"\\staros\\initramfs");

/// Widen an ASCII path to a NUL-terminated UCS-2 array at compile time.
///
/// `N` must be `bytes.len() + 1`; a mismatch is a compile error rather than a
/// truncated path, which is the only way to get this wrong that would still boot
/// far enough to be confusing.
const fn ucs2<const N: usize>(bytes: &[u8]) -> [u16; N] {
    assert!(N == bytes.len() + 1, "UCS-2 buffer must have room for the NUL");
    let mut out = [0u16; N];
    let mut i = 0;
    while i < bytes.len() {
        assert!(bytes[i] < 0x80, "path must be ASCII");
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

/// A file read into memory.
#[derive(Clone, Copy, Debug)]
pub struct Loaded {
    /// Physical base address, page-aligned.
    pub phys: u64,
    /// Length in bytes, as the file system reported it.
    pub len: u64,
}

impl Loaded {
    /// The bytes, as a slice.
    ///
    /// # Safety
    /// Valid while the loader still owns the allocation and the machine is
    /// identity-mapped — that is, until the jump to the kernel.
    #[must_use]
    pub unsafe fn as_slice(&self) -> &'static [u8] {
        // SAFETY: caller upholds the identity-mapping and lifetime conditions;
        // the region was allocated as `len` bytes rounded up to whole pages.
        unsafe { core::slice::from_raw_parts(self.phys as *const u8, self.len as usize) }
    }
}

/// The root directory of the volume this loader came from.
pub struct Volume {
    root: *mut File,
}

impl Volume {
    /// Open the ESP this image was loaded from.
    ///
    /// # Errors
    /// Fails if either protocol is missing or the volume will not open.
    ///
    /// # Safety
    /// `image` and `st` must be the handle and system table passed to `efi_main`.
    pub unsafe fn open(image: Handle, st: &SystemTable) -> Result<Self, Error> {
        // SAFETY: the system table's boot services pointer is valid until
        // ExitBootServices, which has not been called yet.
        let bs = unsafe { &*st.boot_services };

        // SAFETY: `image` is this image's handle; the out-pointer is a local.
        let li: *mut LoadedImage =
            unsafe { handle_protocol(bs, image, &efi::LOADED_IMAGE_GUID, "LoadedImage protocol")? };
        // SAFETY: the firmware returned a valid protocol interface.
        let device = unsafe { (*li).device_handle };

        // SAFETY: `device` is the handle the loaded-image protocol reported.
        let fs: *mut SimpleFileSystem =
            unsafe { handle_protocol(bs, device, &efi::SIMPLE_FS_GUID, "SimpleFileSystem on boot volume")? };

        let mut root: *mut File = core::ptr::null_mut();
        // SAFETY: `fs` is a valid protocol interface; `root` is a valid out-param.
        let status = unsafe { ((*fs).open_volume)(fs, &raw mut root) };
        check("OpenVolume", status)?;
        Ok(Self { root })
    }

    /// Read `\staros\kernel`. Required: without it there is nothing to boot.
    ///
    /// # Errors
    /// Propagates the firmware's status for the open, the size query, the
    /// allocation or the read.
    ///
    /// # Safety
    /// `bs` must be live boot services.
    pub unsafe fn read_kernel(&self, bs: &BootServices) -> Result<Loaded, Error> {
        // SAFETY: forwarded to `read_file`, whose contract this matches.
        unsafe { self.read_file(bs, &KERNEL_PATH, "kernel") }
    }

    /// Read `\staros\initramfs` if it is there. A missing file is `Ok(None)`:
    /// this kernel boots without one, and a hard failure would make an optional
    /// component mandatory by accident.
    ///
    /// # Errors
    /// Only for failures *after* a successful open — a file that exists but
    /// cannot be read is a real error, not an absence.
    ///
    /// # Safety
    /// `bs` must be live boot services.
    pub unsafe fn read_initrd(&self, bs: &BootServices) -> Result<Option<Loaded>, Error> {
        // SAFETY: forwarded to `read_file`.
        match unsafe { self.read_file(bs, &INITRD_PATH, "initramfs") } {
            Ok(l) => Ok(Some(l)),
            Err(e) if e.stage == "open initramfs" => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Open, size, allocate and read one file.
    ///
    /// # Safety
    /// `bs` must be live boot services and `path` NUL-terminated.
    unsafe fn read_file(
        &self,
        bs: &BootServices,
        path: &[u16],
        what: &'static str,
    ) -> Result<Loaded, Error> {
        let mut file: *mut File = core::ptr::null_mut();
        // SAFETY: `self.root` came from OpenVolume; `path` is NUL-terminated.
        let status = unsafe {
            ((*self.root).open)(self.root, &raw mut file, path.as_ptr(), efi::FILE_MODE_READ, 0)
        };
        if efi::is_error(status) {
            // The stage string is load-bearing: `read_initrd` matches on it to
            // tell "absent" from "broken".
            return Err(Error::efi(
                if what == "initramfs" { "open initramfs" } else { "open kernel" },
                status,
            ));
        }

        // EFI_FILE_INFO is variable-length (it ends in the file name), so ask for
        // it into a buffer big enough for any sane name rather than querying the
        // size first: two firmware calls to learn one u64 is two chances to fail.
        let mut info = [0u8; 512];
        let mut info_size = info.len();
        // A local, not `&raw const efi::FILE_INFO_GUID`: a const has no storage,
        // so the address would be of a temporary that dies before the call.
        let info_guid: Guid = efi::FILE_INFO_GUID;
        // SAFETY: `file` is open; the buffer and size out-param are locals.
        let status = unsafe {
            ((*file).get_info)(
                file,
                &raw const info_guid,
                &raw mut info_size,
                info.as_mut_ptr(),
            )
        };
        check("GetInfo(EFI_FILE_INFO)", status)?;

        let len = u64::from_le_bytes(
            info[efi::FILE_INFO_SIZE_OFFSET..efi::FILE_INFO_SIZE_OFFSET + 8]
                .try_into()
                .map_err(|_| Error::own("EFI_FILE_INFO shorter than its own header"))?,
        );
        if len == 0 {
            return Err(Error::own("file on the ESP is empty"));
        }

        // SAFETY: `bs` is live per this function's contract.
        let phys = unsafe { alloc_pages(bs, "allocate pages for file", pages_for(len))? };

        // Read in one call, then insist the firmware gave us everything: a short
        // read is silent otherwise, and a kernel image missing its tail fails
        // later, somewhere unrelated.
        let mut got = len as usize;
        // SAFETY: `phys` covers `len` bytes rounded up to pages, and the loader
        // is identity-mapped, so the physical address is a valid write target.
        let status = unsafe { ((*file).read)(file, &raw mut got, phys as *mut u8) };
        check("Read", status)?;
        // SAFETY: `file` is open and is not used again.
        let _ = unsafe { ((*file).close)(file) };

        if got as u64 != len {
            return Err(Error::own("short read from the ESP"));
        }
        // Zero the slack to the end of the last page. The kernel's ELF parser
        // never looks past `len`, but the initramfs is handed on by address, and
        // uninitialised firmware memory is a poor thing to hand anyone.
        let slack = pages_for(len) as u64 * PAGE_SIZE - len;
        // SAFETY: the allocation is whole pages, so this range is inside it.
        unsafe { core::ptr::write_bytes((phys + len) as *mut u8, 0, slack as usize) };

        Ok(Loaded { phys, len })
    }
}

/// `HandleProtocol`, typed.
///
/// # Safety
/// `bs` must be live, `handle` a valid handle.
unsafe fn handle_protocol<T>(
    bs: &BootServices,
    handle: Handle,
    guid: &Guid,
    stage: &'static str,
) -> Result<*mut T, Error> {
    let mut iface: *mut c_void = core::ptr::null_mut();
    // SAFETY: caller guarantees `bs` and `handle`; the out-param is a local.
    let status = unsafe { (bs.handle_protocol)(handle, guid, &raw mut iface) };
    check(stage, status)?;
    if iface.is_null() {
        return Err(Error::own("firmware returned a null protocol interface"));
    }
    Ok(iface.cast::<T>())
}
