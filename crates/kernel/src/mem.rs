//! Taking ownership of physical memory: the map, the heap, and the frame pool.
//!
//! Three steps, in an order that is forced rather than chosen.
//!
//! 1. **Copy the map.** The firmware's memory map is a buffer the *loader*
//!    allocated, described by a physical address in the hand-off. It sits in
//!    memory the map itself calls `LoaderReclaimable`, and the whole point of
//!    this module is to start handing that memory out. So it is copied into the
//!    kernel's own `.bss` first, before anything can allocate over it.
//! 2. **Carve the heap.** [`BuddyFrameAllocator`] keeps its tree on the heap and
//!    sizes it from the pool, so the heap has to exist before the pool does —
//!    and it cannot come *from* the pool. It is cut off the front of the largest
//!    free run, and the pool gets the rest.
//! 3. **Build the pool.** Everything that is not plainly free is excluded first:
//!    the kernel image, the boot info, the map, an initramfs. All four sit
//!    *inside* ranges the firmware calls usable, so "largest usable range" is not
//!    an answer until they are carved out.
//!
//! The arithmetic for step 3 is [`staros_bootinfo::largest_free_run`], which is
//! host-tested — placing a pool over the kernel image is not a bug that reports
//! itself.

use staros_bootinfo::{BootInfo, MemoryRegion};
use staros_mm::{BuddyFrameAllocator, FrameAllocator, PhysAddr, PAGE_SIZE};

use crate::heap;
use crate::sync::SpinLock;

/// How many map entries the kernel will copy.
///
/// OVMF reports around thirty on a QEMU machine and real firmware rarely exceeds
/// a hundred. The limit exists so the copy is a fixed `.bss` array rather than an
/// allocation — which it has to be, since this runs before the heap.
const MAX_REGIONS: usize = 256;

/// Slack above the frame allocator's tree. Generous on purpose: unused heap is
/// far cheaper than an allocation failure in a kernel with nowhere to fail to.
const HEAP_SLACK: u64 = 1024 * 1024;

/// The kernel's own copy of the firmware memory map.
static mut REGIONS: [MemoryRegion; MAX_REGIONS] =
    [MemoryRegion::new(0, 0, staros_bootinfo::MemoryKind::Reserved); MAX_REGIONS];

/// How many entries of [`REGIONS`] are real.
static COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The frame allocator, or `None` until [`init`] runs.
static FRAMES: SpinLock<Option<BuddyFrameAllocator>> = SpinLock::new(None);

/// What [`init`] worked out, for the boot log and for the mapper.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Total bytes the firmware described.
    pub total: u64,
    /// Bytes it called usable.
    pub usable: u64,
    /// Highest address any region reaches, device apertures included.
    pub highest: u64,
    /// Highest address reached by real memory — how far the linear map must go.
    pub highest_ram: u64,
    /// Physical base and length of the heap.
    pub heap: (u64, u64),
    /// Physical base and length of the frame pool.
    pub pool: (u64, u64),
    /// Frames actually under management (the pool rounded down to a power of two).
    pub managed_frames: usize,
}

/// Why the kernel could not take ownership of memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The map has more entries than [`MAX_REGIONS`].
    MapTooLarge,
    /// No usable range survived the exclusions.
    NoFreeRun,
    /// The largest free run cannot even hold the heap.
    TooSmall,
    /// [`BuddyFrameAllocator::new`] refused the pool.
    PoolRejected,
}

impl Error {
    /// A message naming the failure.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MapTooLarge => "firmware memory map has more entries than the kernel can hold",
            Self::NoFreeRun => "no usable memory left after excluding the kernel and its data",
            Self::TooSmall => "largest free run cannot hold the kernel heap",
            Self::PoolRejected => "frame allocator refused the pool",
        }
    }
}

/// Copy the map, carve the heap, and build the frame pool.
///
/// # Errors
/// See [`Error`]. Every one of them ends the boot: there is no smaller
/// configuration to fall back to.
///
/// `info_phys` is the physical address the loader passed in `RDI`. It is taken
/// separately rather than recovered from the reference, because which address
/// space a pointer belongs to is exactly the thing that stops being obvious once
/// there are two maps of the same memory.
///
/// # Safety
/// `info` must be a validated hand-off whose `memory_map` still points at live
/// memory — that is, called before anything has allocated over it. Called once.
pub unsafe fn init(info: &BootInfo, info_phys: u64) -> Result<Layout, Error> {
    let count = info.memory_map_len as usize;
    if count > MAX_REGIONS {
        return Err(Error::MapTooLarge);
    }

    // Through the linear map rather than the identity map: both reach it today,
    // but the identity map is the loader's scaffolding and `vm::init` is about to
    // stop building it.
    let src = staros_bootinfo::phys_to_virt(info.memory_map) as *const MemoryRegion;
    let dst = &raw mut REGIONS;
    // SAFETY: `REGIONS` is private to this module and nothing has read it yet;
    // `src` is the loader's map, which the caller guarantees is still live, and
    // `count` is bounded by `MAX_REGIONS` above.
    unsafe { core::ptr::copy_nonoverlapping(src, dst.cast::<MemoryRegion>(), count) };
    // SAFETY: the copy above initialised the first `count` entries.
    let regions = unsafe { core::slice::from_raw_parts(dst.cast::<MemoryRegion>(), count) };
    COUNT.store(count, core::sync::atomic::Ordering::SeqCst);

    let stats = staros_bootinfo::summarise(regions);

    // Everything that lives inside memory the firmware calls usable. Missing one
    // means allocating over it, and what breaks depends on which one — the
    // failures range from a corrupt boot log to executing a page table.
    let mut exclusions = [(0u64, 0u64); 4];
    exclusions[0] = (info.kernel_phys, info.kernel_len);
    exclusions[1] = (info.memory_map, (count as u64) * size_of::<MemoryRegion>() as u64);
    // The boot info itself: the loader placed it in its own page.
    exclusions[2] = (info_phys, size_of::<BootInfo>() as u64);
    exclusions[3] = info.initrd().unwrap_or((0, 0));

    let (start, len) =
        staros_bootinfo::largest_free_run(regions, &exclusions).ok_or(Error::NoFreeRun)?;

    // The tree is sized from the pool, and the pool is what is left after the
    // heap — so size the tree from the whole run and accept a slightly larger
    // heap than strictly needed. The alternative is a fixed point iteration to
    // save a few kilobytes.
    let tree = BuddyFrameAllocator::metadata_bytes(len as usize) as u64;
    let heap_len = (tree + HEAP_SLACK).next_multiple_of(PAGE_SIZE as u64);
    if heap_len >= len {
        return Err(Error::TooSmall);
    }
    let (heap_start, pool_start, pool_len) = (start, start + heap_len, len - heap_len);

    // SAFETY: the run came from the map as free, the exclusions kept everything
    // live out of it, it is page-aligned and page-sized, and it is handed over as
    // its linear-map address because the heap writes through it. The pool below
    // starts past the end of it, so nothing else owns these bytes.
    unsafe { heap::init(staros_bootinfo::phys_to_virt(heap_start) as usize, heap_len as usize) };

    let pool = BuddyFrameAllocator::new(PhysAddr(pool_start as usize), pool_len as usize)
        .map_err(|_| Error::PoolRejected)?;
    let managed_frames = pool.frames();
    *FRAMES.lock() = Some(pool);

    Ok(Layout {
        total: stats.total_bytes,
        usable: stats.usable_bytes,
        highest: stats.highest_address,
        highest_ram: stats.highest_ram,
        heap: (heap_start, heap_len),
        pool: (pool_start, pool_len),
        managed_frames,
    })
}

/// The kernel's copy of the memory map. Empty before [`init`].
#[must_use]
pub fn regions() -> &'static [MemoryRegion] {
    let count = COUNT.load(core::sync::atomic::Ordering::SeqCst);
    let ptr = (&raw const REGIONS).cast::<MemoryRegion>();
    // SAFETY: `init` wrote exactly `count` entries and nothing writes the array
    // afterwards, so this is a shared borrow of initialised, immutable data.
    unsafe { core::slice::from_raw_parts(ptr, count) }
}

/// Print the memory map, coalescing runs of the same kind.
///
/// Firmware maps are long and mostly boring — OVMF reports thirty entries for a
/// machine with two interesting ones. Adjacent entries of the same kind are
/// merged so what is printed is the *shape* of the machine's memory rather than
/// the shape of the firmware's bookkeeping.
pub fn describe(console: &mut crate::console::Console) {
    use core::fmt::Write;

    let mut run: Option<(u64, u64, staros_bootinfo::MemoryKind)> = None;
    let mut lines = 0usize;
    for r in regions().iter().filter(|r| r.len > 0) {
        match run {
            Some((start, end, kind)) if kind == r.kind && end == r.start => {
                run = Some((start, r.end(), kind));
            }
            other => {
                if let Some((start, end, kind)) = other {
                    emit(console, start, end, kind, &mut lines);
                }
                run = Some((r.start, r.end(), r.kind));
            }
        }
    }
    if let Some((start, end, kind)) = run {
        emit(console, start, end, kind, &mut lines);
    }

    fn emit(
        console: &mut crate::console::Console,
        start: u64,
        end: u64,
        kind: staros_bootinfo::MemoryKind,
        lines: &mut usize,
    ) {
        // The console is 100 rows; a hostile firmware map must not push the rest
        // of the boot off the top of it.
        const MAX_LINES: usize = 16;
        *lines += 1;
        if *lines > MAX_LINES {
            if *lines == MAX_LINES + 1 {
                let _ = writeln!(console, "  ... (map truncated)");
            }
            return;
        }
        let name = match kind {
            staros_bootinfo::MemoryKind::Usable => "usable",
            staros_bootinfo::MemoryKind::Reserved => "reserved",
            staros_bootinfo::MemoryKind::AcpiReclaimable => "acpi reclaimable",
            staros_bootinfo::MemoryKind::AcpiNvs => "acpi nvs",
            staros_bootinfo::MemoryKind::LoaderReclaimable => "loader",
            staros_bootinfo::MemoryKind::BadMemory => "bad",
        };
        let _ = writeln!(console, "  {start:#014x}..{end:#014x}  {:>8} KiB  {name}", (end - start) / 1024);
    }
}

/// Run `f` with exclusive access to the frame allocator.
///
/// # Panics
/// If [`init`] has not run.
pub fn with<R>(f: impl FnOnce(&mut BuddyFrameAllocator) -> R) -> R {
    let mut slot = FRAMES.lock();
    let alloc = slot.as_mut().expect("frame allocator used before init");
    f(alloc)
}

/// Allocate one frame, or `None` when memory is exhausted.
pub fn alloc_frame() -> Option<PhysAddr> {
    with(|a| a.allocate())
}

/// Return a frame to the pool.
pub fn free_frame(frame: PhysAddr) {
    with(|a| a.free_pages(frame));
}

/// The longest run of contiguous free frames.
///
/// The cheapest honest answer to "did everything come back?": it equals the
/// managed frame count exactly when the pool is entirely free *and* fully
/// coalesced, so one leaked frame anywhere drops it.
pub fn largest_free_run() -> usize {
    with(|a| a.largest_free_run())
}

/// Allocate and free until the pool has to coalesce, and check that it did.
///
/// The same test the aarch64 tree runs, and it works because
/// [`BuddyFrameAllocator::largest_free_run`] is a property of the *tree*, not a
/// count: it equals the managed frame count only when every frame is free **and**
/// every buddy has been merged back. One leaked frame in the middle of the pool
/// halves it. So a single number, compared before and after, catches both a leak
/// and a failure to coalesce, without the allocator tracking owners.
///
/// Sizes and free order come from a fixed-seed xorshift, so a failure is
/// reproducible — a random order that cannot be replayed is not a test, it is an
/// anecdote.
pub fn selftest(console: &mut crate::console::Console) {
    use core::fmt::Write;

    /// xorshift64. Not for anything that needs to be unpredictable; this needs
    /// the opposite.
    fn next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    const ROUNDS: usize = 4;
    const BLOCKS: usize = 64;

    let before = largest_free_run();
    let mut rng = 0x2545_F491_4F6C_DD1D_u64;
    let mut held = [PhysAddr(0); BLOCKS];
    let mut failures = 0usize;

    for round in 0..ROUNDS {
        let mut n = 0usize;
        for slot in held.iter_mut() {
            // 1, 2, 4 or 8 frames: enough splitting for buddies to matter.
            let frames = 1usize << (next(&mut rng) % 4);
            let Some(block) = with(|a| a.alloc_pages(frames)) else { break };
            *slot = block;
            n += 1;
        }
        if n == 0 {
            let _ = writeln!(console, "frames: pool refused every allocation in round {round}");
            failures += 1;
            break;
        }
        // Free in an order unrelated to the order they were taken, so coalescing
        // has to happen from both sides.
        for i in (0..n).rev() {
            let j = (next(&mut rng) as usize) % (i + 1);
            held.swap(i, j);
        }
        for &block in &held[..n] {
            free_frame(block);
        }
        let after = largest_free_run();
        if after != before {
            let _ = writeln!(
                console,
                "frames: round {round} did not converge - {after} frames free, expected {before}"
            );
            failures += 1;
        }
    }

    if failures == 0 {
        let _ = writeln!(
            console,
            "frames: {ROUNDS} rounds of up to {BLOCKS} allocations converged, \
             largest free run back to {before} frames (the page tables hold the rest)"
        );
    }
}
