//! Taking ownership of physical memory: the map, the heap, and the frame pool.
//!
//! Three steps, in an order that is forced rather than chosen.
//!
//! 1. **Copy the map.** The firmware's memory map is a buffer the *loader*
//!    allocated, described by a physical address in the hand-off. It sits in
//!    memory the map itself calls `LoaderReclaimable`, and the whole point of
//!    this module is to start handing that memory out. So it is copied into the
//!    kernel's own `.bss` first, before anything can allocate over it.
//! 2. **Carve the heap.** [`FramePool`] keeps its trees on the heap and sizes
//!    them from the memory it manages, so the heap has to exist before the pool
//!    does — and it cannot come *from* the pool. It is cut off the front of the
//!    largest free run, and the pool gets the rest of that one plus every other
//!    run whole.
//! 3. **Build the pool.** Everything that is not plainly free is excluded first:
//!    the kernel image, the boot info, the map, an initramfs. All four sit
//!    *inside* ranges the firmware calls usable, so "usable ranges" is not an
//!    answer until they are carved out.
//!
//! The arithmetic for step 3 is [`staros_bootinfo::free_runs`], which is
//! host-tested — placing a pool over the kernel image is not a bug that reports
//! itself.
//!
//! ## Every run, not the largest
//! This used to take `largest_free_run` and hand that one run to one buddy tree,
//! which rounds down to a power of two. On a 4 GiB PC that managed 1024 MiB of
//! 4041: half the machine lost to the PCI hole splitting RAM in two, and half of
//! what was left lost to the rounding. The number was even asserted by the boot
//! matrix — visible, and still wrong.
//!
//! Now every free run goes in, and [`FramePool`] decomposes each into its binary
//! expansion so nothing is rounded away. The same machine manages 4032 MiB. The
//! price is metadata: four times as many frames tracked, so the heap grows from
//! 3 MiB to 9 MiB, which is 0.2% of the memory it makes usable.

use staros_bootinfo::{BootInfo, MemoryRegion};
use staros_mm::{FramePool, PhysAddr, PAGE_SIZE};

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
static FRAMES: SpinLock<Option<FramePool>> = SpinLock::new(None);

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
    /// How many separate free runs the pool was given.
    pub pool_runs: usize,
    /// How many buddy trees those runs decomposed into.
    pub pool_trees: usize,
    /// Total bytes handed to the pool.
    pub pool_bytes: u64,
    /// Free runs that existed but did not fit in the fixed-size array. Memory the
    /// kernel is knowingly not using, and it says so rather than losing it
    /// quietly.
    pub truncated_runs: usize,
    /// Frames actually under management. Equal to `pool_bytes / PAGE_SIZE` now
    /// that nothing is rounded away — which is the point, and why it is still
    /// reported separately rather than assumed.
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

    // Every free run, not the largest. The difference is most of the machine: a
    // 4 GiB PC splits RAM either side of the PCI hole, and the exclusions above
    // cut two more holes in whichever half the kernel landed in.
    let mut runs = [(0u64, 0u64); staros_bootinfo::MAX_FREE_RUNS];
    let found = staros_bootinfo::free_runs(regions, &exclusions, &mut runs);
    let kept = found.min(runs.len());
    if kept == 0 {
        return Err(Error::NoFreeRun);
    }
    let runs = &mut runs[..kept];

    // The heap has to exist before the pool, because the pool's trees live on it —
    // and it has to be carved out of one of these same runs, because there is
    // nowhere else. The largest run pays for it; the pool gets what is left of
    // that one plus all the others whole.
    //
    // Sizing it needs the *total*, since the pool now manages every run. This
    // over-estimates slightly: the heap is subtracted from a run after the bill is
    // computed, so the bill covers a few frames the pool will not get. Paying a
    // kilobyte to avoid a fixed-point iteration.
    let mut as_usize = [(0usize, 0usize); staros_bootinfo::MAX_FREE_RUNS];
    for (dst, &(start, len)) in as_usize.iter_mut().zip(runs.iter()) {
        *dst = (start as usize, len as usize);
    }
    let trees = FramePool::metadata_bytes_for(&as_usize[..kept]) as u64;
    let heap_len = (trees + HEAP_SLACK).next_multiple_of(PAGE_SIZE as u64);

    // Take the heap off the front of the largest run, so the shortening costs the
    // pool its least useful frames rather than fragmenting a small run away
    // entirely.
    let biggest = runs
        .iter()
        .enumerate()
        .max_by_key(|(_, &(_, len))| len)
        .map(|(i, _)| i)
        .ok_or(Error::NoFreeRun)?;
    if runs[biggest].1 <= heap_len {
        return Err(Error::TooSmall);
    }
    let heap_start = runs[biggest].0;
    runs[biggest] = (heap_start + heap_len, runs[biggest].1 - heap_len);

    // SAFETY: the run came from the map as free, the exclusions kept everything
    // live out of it, it is page-aligned and page-sized, and it is handed over as
    // its linear-map address because the heap writes through it. The pool below is
    // given the rest of that run and never these bytes.
    unsafe { heap::init(staros_bootinfo::phys_to_virt(heap_start) as usize, heap_len as usize) };

    let mut pool = FramePool::new();
    for &(start, len) in runs.iter() {
        // A run too short for a whole frame adds nothing and is not an error;
        // firmware maps are full of them.
        pool.add(PhysAddr(start as usize), len as usize)
            .map_err(|_| Error::PoolRejected)?;
    }
    let managed_frames = pool.frames();
    let pool_trees = pool.trees();
    let pool_bytes = runs.iter().map(|&(_, len)| len).sum();
    *FRAMES.lock() = Some(pool);

    Ok(Layout {
        total: stats.total_bytes,
        usable: stats.usable_bytes,
        highest: stats.highest_address,
        highest_ram: stats.highest_ram,
        heap: (heap_start, heap_len),
        pool_runs: kept,
        pool_trees,
        pool_bytes,
        truncated_runs: found.saturating_sub(kept),
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
pub fn with<R>(f: impl FnOnce(&mut FramePool) -> R) -> R {
    let mut slot = FRAMES.lock();
    let alloc = slot.as_mut().expect("frame allocator used before init");
    f(alloc)
}

/// Frames handed out by [`alloc_frame`] and not yet returned by [`free_frame`].
///
/// Only those two. Anything that reaches the pool through [`with`] — the
/// multi-frame blocks the self-test below takes — is invisible here, and must
/// free the same way it allocated.
///
/// A ledger the kernel keeps for itself, and it exists because the allocator's
/// own answer is the wrong shape. [`coalesced_frames`] is the sum over trees of
/// each tree's *largest free run*: it equals the managed total exactly when the
/// pool is entirely free and fully coalesced, which makes it a perfect end-of-boot
/// check and a useless mid-run one. Once anything is held permanently — and from
/// phase 3.1 something is, the shared tick page — the largest free block has
/// already been cut, and cutting it again with fourteen more frames may not change
/// the number at all. Leaking a whole task's page tables went undetected by it.
///
/// A count of outstanding frames has no such blind spot: build an address space
/// and tear it down, and this must return to exactly the value it had.
static IN_USE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Allocate one frame, or `None` when memory is exhausted.
pub fn alloc_frame() -> Option<PhysAddr> {
    let frame = with(|a| a.alloc_pages(1));
    if frame.is_some() {
        IN_USE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    frame
}

/// Return a frame to the pool.
pub fn free_frame(frame: PhysAddr) {
    with(|a| a.free_pages(frame));
    IN_USE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
}

/// How many frames are currently handed out. See [`IN_USE`].
#[must_use]
pub fn frames_in_use() -> u64 {
    IN_USE.load(core::sync::atomic::Ordering::Relaxed)
}


/// The sum, over the pool's trees, of each tree's longest free run.
///
/// The cheapest honest answer to "did everything come back?": it equals the
/// managed frame count exactly when every tree is entirely free *and* fully
/// coalesced, so one leaked frame in any tree drops it.
///
/// Not `largest_free_run`, which is the largest single allocation the pool could
/// satisfy — a useful number, and the wrong one for this question now that there
/// is more than one tree.
pub fn coalesced_frames() -> usize {
    with(|a| a.coalesced_frames())
}

/// Allocate and free until the pool has to coalesce, and check that it did.
///
/// The same test the aarch64 tree runs, and it works because
/// [`coalesced_frames`] is a property of the *trees*, not a count: it equals the
/// managed frame count only when every frame is free **and** every buddy has been
/// merged back. One leaked frame anywhere drops it. So a single number, compared
/// before and after, catches both a leak and a failure to coalesce, without the
/// allocator tracking owners.
///
/// Sizes and free order come from a fixed-seed xorshift, so a failure is
/// reproducible — a random order that cannot be replayed is not a test, it is an
/// anecdote.
///
/// Returns whether every round converged, so the boot does not go on to claim a
/// phase it did not finish.
pub fn selftest(console: &mut crate::console::Console) -> bool {
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

    let before = coalesced_frames();
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
            let _ = writeln!(
                console,
                "frames SELF-TEST FAILED: the pool refused every allocation in round {round}"
            );
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
            // The pool directly, not `free_frame`: this test takes *blocks* with
            // `alloc_pages`, which the ledger in `IN_USE` does not see, and a free
            // it did see would drive the count negative. The two must be symmetric
            // or the ledger measures the test instead of the kernel.
            with(|a| a.free_pages(block));
        }
        let after = coalesced_frames();
        if after != before {
            let _ = writeln!(
                console,
                "frames SELF-TEST FAILED: round {round} did not converge - \
                 {after} frames free, expected {before}"
            );
            failures += 1;
        }
    }

    if failures == 0 {
        let _ = writeln!(
            console,
            "frames: {ROUNDS} rounds of up to {BLOCKS} allocations converged, \
             {before} frames free and coalesced (the page tables hold the rest)"
        );
    }
    failures == 0
}
