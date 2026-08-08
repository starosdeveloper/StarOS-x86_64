//! Memory-mapped 32-bit registers, as a trait.
//!
//! The same reasoning as [`crate::port::PortIo`], for the devices that are not
//! in the port space. An I/O APIC is programmed through *two* registers — write
//! an index to one, then read or write the other — so every access is a
//! sequence, and a sequence with the halves swapped is accepted by the hardware
//! and produces a controller that routes nothing. Behind a trait, the sequence
//! is data the host tests can read back.
//!
//! Reads and writes are `volatile` in the real implementation and that is not
//! optional: to the compiler an MMIO register looks like ordinary memory nobody
//! else touches, so two writes to the same address collapse into one and a read
//! whose result is unused disappears. Both are correct for memory and wrong for
//! a device.

/// Access to a device's 32-bit registers, by byte offset from its base.
///
/// # Safety
/// Implementors must direct accesses to the device's registers (or, in a test,
/// to a faithful model of them), with each access performed exactly once and in
/// program order.
pub unsafe trait Mmio32 {
    /// Read the register at `offset` bytes from the base.
    fn read(&mut self, offset: usize) -> u32;
    /// Write the register at `offset` bytes from the base.
    fn write(&mut self, offset: usize, value: u32);
}

/// The same, for devices whose registers are 64 bits wide.
///
/// A separate trait rather than two more methods on [`Mmio32`], because the
/// devices genuinely differ: the APICs are 32-bit registers on 16-byte centres
/// and reading one as 64 bits reads a reserved word with it, while the HPET's
/// main counter is a single 64-bit register and reading it as two 32-bit halves
/// can straddle a carry — returning a time that never existed. Which width a
/// device wants is a property of the device, so it is in the type.
///
/// # Safety
/// As [`Mmio32`], and each access must be a single 64-bit operation rather than
/// two 32-bit ones.
pub unsafe trait Mmio64 {
    /// Read the 64-bit register at `offset` bytes from the base.
    fn read64(&mut self, offset: usize) -> u64;
    /// Write the 64-bit register at `offset` bytes from the base.
    fn write64(&mut self, offset: usize, value: u64);
}

/// A device's registers, reached through a mapping the kernel made.
pub struct MappedRegisters {
    base: *mut u8,
}

// SAFETY: the pointer is a kernel virtual address of device registers, and a
// kernel mapping means the same thing on every core — unlike a pointer into a
// per-core structure or a thread's stack. Moving the handle between cores
// therefore moves nothing that was core-specific. What must not happen is *two*
// handles to the same device existing at once, and that is `new`'s contract
// rather than something `Send` could express.
unsafe impl Send for MappedRegisters {}

impl MappedRegisters {
    /// Wrap a virtual address the caller has mapped.
    ///
    /// # Safety
    /// `base` must be a live mapping of the device's registers, made **device
    /// memory** rather than ordinary RAM — see
    /// [`staros_paging::MemoryType::Device`]. It must remain mapped for as long
    /// as this value exists, and nothing else may drive the same device.
    #[must_use]
    pub const unsafe fn new(base: u64) -> Self {
        Self { base: base as *mut u8 }
    }

    /// The virtual base this was built from.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base as u64
    }
}

// SAFETY: `new`'s contract makes `base` a live device mapping; every access here
// is a single volatile 32-bit operation at a 4-byte aligned offset, which is what
// every register this kernel touches requires.
unsafe impl Mmio32 for MappedRegisters {
    fn read(&mut self, offset: usize) -> u32 {
        debug_assert!(offset.is_multiple_of(4), "MMIO register offsets are 4-byte aligned");
        // SAFETY: as above.
        unsafe { self.base.add(offset).cast::<u32>().read_volatile() }
    }

    fn write(&mut self, offset: usize, value: u32) {
        debug_assert!(offset.is_multiple_of(4), "MMIO register offsets are 4-byte aligned");
        // SAFETY: as above.
        unsafe { self.base.add(offset).cast::<u32>().write_volatile(value) };
    }
}

// SAFETY: as the 32-bit implementation, with 8-byte accesses at 8-byte aligned
// offsets. `read_volatile` of a `u64` is one instruction on x86-64, which is what
// makes reading the HPET's counter atomic with respect to its own carry.
unsafe impl Mmio64 for MappedRegisters {
    fn read64(&mut self, offset: usize) -> u64 {
        debug_assert!(offset.is_multiple_of(8), "64-bit registers are 8-byte aligned");
        // SAFETY: as above.
        unsafe { self.base.add(offset).cast::<u64>().read_volatile() }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        debug_assert!(offset.is_multiple_of(8), "64-bit registers are 8-byte aligned");
        // SAFETY: as above.
        unsafe { self.base.add(offset).cast::<u64>().write_volatile(value) };
    }
}
