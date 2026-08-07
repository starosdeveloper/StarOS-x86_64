//! The kernel's global heap, wired to Rust's `alloc` via [`GlobalAlloc`].
//!
//! The algorithm is [`staros_mm::heap`] — portable, host-tested, and the same
//! code the aarch64 tree runs. This module only holds the region and serialises
//! access to it.
//!
//! **The region is carved out of the RAM the firmware reported**, not baked in
//! as a static array, because its main consumer sizes itself from the machine
//! too: the frame allocator's tree costs
//! [`BuddyFrameAllocator::metadata_bytes`](staros_mm::BuddyFrameAllocator::metadata_bytes)
//! — 8 bytes per frame, so 4 MiB to manage 2 GiB. A fixed heap would either
//! waste memory on a small machine or fail to manage a large one.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use staros_mm::heap::FreeListAllocator;

use crate::sync::SpinLock;

/// The global allocator: the portable free list plus the region it manages.
struct KernelHeap(SpinLock<FreeListAllocator>);

#[global_allocator]
static ALLOCATOR: KernelHeap = KernelHeap(SpinLock::new(FreeListAllocator::new()));

/// Hand the heap the region `[start, start + len)`, addressed as the *kernel*
/// sees it — these bytes are handed out to Rust code as `&mut` data, so `start`
/// is a virtual address in the linear map, not the physical address the run was
/// carved from.
///
/// # Safety
/// Called exactly once, before the first allocation, with a region that is
/// mapped and writable, owned by nobody else (in particular excluded from the
/// frame pool), 16-byte aligned and a multiple of 16 bytes long.
pub unsafe fn init(start: usize, len: usize) {
    // SAFETY: called once during early boot; the region meets the allocator's
    // alignment and size contract per this function's own.
    unsafe {
        ALLOCATOR.0.lock().init(start as *mut u8, len);
    }
}

// SAFETY: `alloc`/`dealloc` uphold the `GlobalAlloc` contract — each returns a
// pointer to `layout`-sized, `layout`-aligned memory (or null), and `dealloc`
// only ever receives a pointer from a prior `alloc` with the same layout. The
// lock makes each update atomic against both other cores and this core's own
// interrupt handlers.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // The guard is exclusive access to the free list; `alloc` is safe once
        // you have it.
        let result = self.0.lock().alloc(layout);
        result.map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some(nn) = NonNull::new(ptr) else { return };
        // SAFETY: `ptr`/`layout` come from a prior `alloc` per the contract.
        unsafe { self.0.lock().dealloc(nn, layout) };
    }
}
