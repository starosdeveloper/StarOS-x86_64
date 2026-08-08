//! A page-table tree of its own for each ring-3 task.
//!
//! Until phase 3.2 there was one tree. The ring-3 program of 3.1 lived in the
//! *kernel's* tree with a few user-accessible pages hung off the bottom of it,
//! which is enough to prove `iretq` and `syscall` work and proves nothing at all
//! about isolation: one program cannot be isolated from itself.
//!
//! ## What x86 makes different, and it is the whole design
//! AArch64 has two translation base registers. `TTBR1` holds the kernel and never
//! changes; `TTBR0` holds the current process and is swapped on every switch. The
//! split is hardware, and a user task simply cannot name a kernel address —
//! there is no entry for it to walk.
//!
//! x86-64 has one. `CR3` points at a single four-level tree covering the whole
//! canonical address space, and the kernel and the process live in the same one:
//! kernel in the upper half (PML4 entries 256–511), process in the lower
//! (0–255). So "a private address space" here means **a private PML4 whose upper
//! half is a copy of the kernel's**, and a switch is a whole `CR3` reload rather
//! than half of one.
//!
//! Copying *entries*, not subtrees: entry 256 of every tree points at the same
//! PDPT frame, so the kernel's linear map, its image and its stacks are one set
//! of tables shared by every space. Any kernel mapping made *below* an existing
//! PML4 entry appears in every space at once, which is what makes it safe to
//! switch `CR3` while executing kernel code — the instruction after the write is
//! mapped identically in the tree being left and the one being entered. What
//! would *not* propagate is a brand-new top-level entry, so the kernel's own
//! upper half must be complete before the first space is built. It is: `vm::init`
//! runs long before this module does.
//!
//! ## Rights
//! Every leaf here carries `PTE_USER`, and the walk ANDs `user` down the levels,
//! so a page is reachable from ring 3 only if every table above it says so too.
//! Segment rights come from the ELF's `p_flags` and are applied as they are: a
//! read-execute segment gets no write bit, a read-write one gets `NX`. The loader
//! refuses a segment that asks for both, which is a build mistake at the moment
//! it can still be called one rather than an exploit primitive later.
//!
//! ## Teardown
//! [`AddressSpace::destroy`] walks the lower half and returns every frame — the
//! data pages and the tables that reach them. It has to, or a task that faults
//! costs the machine its memory permanently and nothing in the log looks
//! different; phase 2.4 learned that lesson about kernel stacks and this is the
//! same lesson about address spaces. What it deliberately does not free is the
//! *borrowed* frame: the tick counter is one page the kernel owns and maps into
//! every space, and freeing it twice would hand the same frame to two tasks.

use staros_elf64::Elf;
use staros_paging::{
    Mapper, Rights, PAGE_SIZE, PTE_ADDR_MASK, PTE_HUGE, PTE_PRESENT, PTE_USER,
};

use crate::mem;
use crate::vm::{KernelFrames, Tables, USER_LIMIT};

/// First PML4 slot belonging to the kernel half. Everything from here up is
/// copied from the kernel's tree and never freed by a space that borrowed it.
const KERNEL_PML4_FIRST: usize = 256;

/// Where a task's stack lives: one page, top exclusive.
pub const USER_STACK: u64 = 0x0000_0000_7FFF_F000;
/// The stack pointer a task starts with — page aligned, so 16-byte aligned.
pub const USER_STACK_TOP: u64 = USER_STACK + PAGE_SIZE;

/// The kernel-seeded page holding this task's process id.
///
/// Sixteen gigabytes above the image, and that gap is the point: the tree is
/// sparse, so the distance costs three tables rather than four million pages. A
/// program placed next to its image would prove nothing about that.
pub const USER_DATA_VA: u64 = 0x0000_0004_0000_0000;

/// The kernel-published tick counter, read-only to ring 3, one page above the id.
pub const USER_CLOCK_VA: u64 = 0x0000_0004_0001_0000;

/// One ring-3 address space.
///
/// `Copy` and small: it is a handle to a tree, not the tree. The scheduler stores
/// one per task and hands it around under a lock it does not hold across a
/// switch, which a heap-owning type would make awkward for no benefit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace {
    /// Physical address of this space's PML4 — the value that goes in `CR3`.
    root: u64,
    /// The program's entry point, from the ELF's `e_entry`.
    entry: u64,
    /// Whether the kernel's linear map uses 1 GiB pages. Carried so a walk of
    /// this tree resolves the shared upper half the same way `vm` built it.
    gib_pages: bool,
    /// A frame mapped here that this space does **not** own, and must not free.
    /// Today that is the shared tick counter; there is exactly one.
    borrowed: Option<u64>,
}

impl AddressSpace {
    /// Build an empty space: a fresh PML4 with the kernel's upper half copied in
    /// and nothing at all in the lower.
    ///
    /// # Errors
    /// When the pool cannot supply a frame. Fallible rather than panicking
    /// because "the machine is out of memory" is an answer a caller must be able
    /// to receive, and from phase 3.3 a *user* will be able to provoke it.
    pub fn new(tables: &Tables) -> Result<Self, &'static str> {
        let root = mem::alloc_frame().ok_or("no frame for a user PML4")?.0 as u64;
        let table = staros_bootinfo::phys_to_virt(root) as *mut u64;
        // SAFETY: a frame just allocated exclusively from the pool and mapped
        // read/write through the linear map. Zeroing first is not optional — the
        // buddy allocator recycles frames without clearing them, and a PML4 read
        // as garbage is 512 entries pointing at arbitrary memory with arbitrary
        // rights, half of them in the user half.
        unsafe { core::ptr::write_bytes(table.cast::<u8>(), 0, PAGE_SIZE as usize) };

        let kernel_table = staros_bootinfo::phys_to_virt(tables.root) as *const u64;
        for slot in KERNEL_PML4_FIRST..512 {
            // SAFETY: both frames are page-aligned, 512 entries long, and reached
            // through the linear map; `slot` is in range by construction.
            unsafe { table.add(slot).write(kernel_table.add(slot).read()) };
        }

        Ok(Self { root, entry: 0, gib_pages: tables.gib_pages, borrowed: None })
    }

    /// The value to load into `CR3` to make this space current.
    #[must_use]
    pub const fn root(&self) -> u64 {
        self.root
    }

    /// Where ring 3 begins executing.
    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Load every `PT_LOAD` segment of `image` into this space.
    ///
    /// Each segment gets its own fresh frames, its bytes copied in through the
    /// *linear map*, and the rights its `p_flags` asked for. The copy goes
    /// through the kernel's own alias rather than through the address it will be
    /// mapped at, and that is not a preference: `CR4.SMAP` has been on since
    /// phase 1.4, so a ring-0 store to a user-mapped page faults.
    ///
    /// The zero-filled tail — `p_memsz` beyond `p_filesz`, which is `.bss` —
    /// comes free, because every frame is zeroed before anything is copied into
    /// it. That is worth stating rather than assuming: a loader that skipped it
    /// would hand a program whatever the frame last held, which on a machine that
    /// has been running is another task's data.
    ///
    /// # Errors
    /// Names the segment problem, or the exhaustion, that stopped the load.
    pub fn load(&mut self, image: &Elf<'_>) -> Result<(), &'static str> {
        for segment in image.segments() {
            let segment = segment.map_err(staros_elf64::ElfError::as_str)?;
            if segment.rights.is_wx() {
                // A build mistake, reported where it is still a build mistake.
                return Err("the image has a segment that is both writable and executable");
            }
            if segment.vaddr >= USER_LIMIT || segment.memsz > USER_LIMIT - segment.vaddr {
                return Err("a segment does not fit in the user half of the address space");
            }

            let rights = Rights {
                write: segment.rights.write,
                exec: segment.rights.exec,
                user: true,
            };

            let mut copied = 0usize;
            for page in 0..segment.pages() {
                let virt = segment.vaddr + page * PAGE_SIZE;
                let frame = mem::alloc_frame().ok_or("no frame for a program segment")?.0 as u64;
                let kernel_va = staros_bootinfo::phys_to_virt(frame) as *mut u8;
                let take = core::cmp::min(PAGE_SIZE as usize, segment.file.len() - copied);
                // SAFETY: a frame just allocated exclusively, mapped read/write
                // through the linear map, a whole page long. The source is inside
                // the image slice by construction of `take`, and the two cannot
                // overlap — one is the kernel's `.rodata`, the other a pool frame.
                unsafe {
                    core::ptr::write_bytes(kernel_va, 0, PAGE_SIZE as usize);
                    if take > 0 {
                        core::ptr::copy_nonoverlapping(
                            segment.file.as_ptr().add(copied),
                            kernel_va,
                            take,
                        );
                    }
                }
                copied += take;
                self.map(virt, frame, rights)?;
            }
        }
        self.entry = image.entry();
        if self.entry >= USER_LIMIT {
            return Err("the image's entry point is not a user address");
        }
        Ok(())
    }

    /// Give this space a stack: one zeroed, writable, non-executable page.
    ///
    /// Zeroed for the same reason the segments are — a recycled frame handed to
    /// ring 3 is a disclosure — and non-executable because a stack that can be
    /// executed is where a smashed one becomes code.
    ///
    /// # Errors
    /// When the pool cannot supply the frame.
    pub fn map_stack(&mut self) -> Result<(), &'static str> {
        let frame = mem::alloc_frame().ok_or("no frame for a user stack")?.0 as u64;
        let kernel_va = staros_bootinfo::phys_to_virt(frame) as *mut u8;
        // SAFETY: as `load` — a freshly allocated frame reached through the
        // linear map.
        unsafe { core::ptr::write_bytes(kernel_va, 0, PAGE_SIZE as usize) };
        self.map(USER_STACK, frame, Rights::RW.to_user())
    }

    /// Seed the per-process page at [`USER_DATA_VA`] with `id`.
    ///
    /// The one byte that makes two tasks running the same image at the same
    /// address do different things — and the one that makes the difference
    /// *visible*, because the program prints it.
    ///
    /// # Errors
    /// When the pool cannot supply the frame.
    pub fn seed_id(&mut self, id: u8) -> Result<(), &'static str> {
        let frame = mem::alloc_frame().ok_or("no frame for the process id page")?.0 as u64;
        let kernel_va = staros_bootinfo::phys_to_virt(frame) as *mut u8;
        // SAFETY: as `load`.
        unsafe {
            core::ptr::write_bytes(kernel_va, 0, PAGE_SIZE as usize);
            kernel_va.write(id);
        }
        self.map(USER_DATA_VA, frame, Rights::RW.to_user())
    }

    /// Map the kernel's tick counter here, read-only.
    ///
    /// `frame` belongs to the kernel and is mapped into every space, so it is
    /// recorded as [`AddressSpace::borrowed`] and [`AddressSpace::destroy`] steps
    /// over it. Read-only: a task needs to know the time to bound its own loop
    /// and has no business setting it.
    ///
    /// # Errors
    /// When the mapping cannot be built.
    pub fn map_clock(&mut self, frame: u64) -> Result<(), &'static str> {
        self.borrowed = Some(frame);
        self.map(USER_CLOCK_VA, frame, Rights::RO.to_user())
    }

    /// Add one page to this space.
    fn map(&mut self, virt: u64, phys: u64, rights: Rights) -> Result<(), &'static str> {
        if !rights.user {
            return Err("a user mapping without the user bit is one ring 3 cannot use");
        }
        let mut frames = KernelFrames;
        let mut mapper = Mapper::adopt(self.root, &mut frames, self.gib_pages);
        mapper
            .map(virt, phys, PAGE_SIZE, rights)
            .map_err(staros_paging::MapError::as_str)
    }

    /// Where `virt` lands in this space, if anywhere. For the boot log: printing
    /// the physical address the *same* virtual address resolves to in two spaces
    /// is the shortest proof that they are two spaces.
    #[must_use]
    pub fn translate(&self, virt: u64) -> Option<u64> {
        let mut frames = KernelFrames;
        let mut mapper = Mapper::adopt(self.root, &mut frames, self.gib_pages);
        mapper.translate(virt).map(|t| t.phys)
    }

    /// Whether ring 3 may read — and, if `write`, write — every byte of
    /// `[ptr, ptr + len)` **in this space**.
    ///
    /// The check the kernel owes itself before dereferencing anything a syscall
    /// handed it, and it walks the tables rather than testing a range. Being in
    /// the user half proves only that an address is not the kernel's: it may be
    /// unmapped, or mapped for the kernel alone, and dereferencing either from
    /// ring 0 is a fault in the kernel. `translate` returns the rights the *walk*
    /// computes — the AND of `user` and `write` down every level — which is what
    /// the CPU enforces and what a check against the leaf alone would get wrong.
    #[must_use]
    pub fn range_ok(&self, ptr: u64, len: u64, write: bool) -> bool {
        if len == 0 {
            return true;
        }
        if ptr >= USER_LIMIT || len > USER_LIMIT - ptr {
            return false;
        }
        let mut frames = KernelFrames;
        let mut mapper = Mapper::adopt(self.root, &mut frames, self.gib_pages);
        let first = ptr & !(PAGE_SIZE - 1);
        // `len - 1`: a range ending exactly on a page boundary does not touch the
        // next page, and demanding that page be mapped would reject a valid one.
        let last = (ptr + len - 1) & !(PAGE_SIZE - 1);
        let mut page = first;
        loop {
            match mapper.translate(page) {
                Some(t) if t.rights.user && (!write || t.rights.write) => {}
                _ => return false,
            }
            if page == last {
                return true;
            }
            page += PAGE_SIZE;
        }
    }

    /// Return every frame this space owns — its data pages, its page tables, and
    /// the PML4 itself — and report how many.
    ///
    /// Walks only the lower half. The upper half is the kernel's, reached through
    /// entries this space *copied*; freeing any of it would hand the linear map
    /// back to the allocator while every other space is still using it.
    ///
    /// # Safety
    /// This space must not be the one in `CR3`. Freeing the tree the CPU is
    /// walking is a fault with no report — the next translation resolves through
    /// memory that has been handed to somebody else.
    #[must_use]
    pub unsafe fn destroy(self) -> usize {
        let mut freed = 0usize;
        let borrowed = self.borrowed;
        // SAFETY: forwarded from this function's contract; every frame reached
        // below came from `mem::alloc_frame` through this space's own mapping
        // calls, and nothing else holds it.
        unsafe {
            freed += free_level(self.root, 4, borrowed);
            mem::free_frame(staros_mm::PhysAddr(self.root as usize));
        }
        freed + 1
    }
}

/// Free the lower half of the tree rooted at `table`, which is at `level`
/// (4 = PML4). Returns how many frames were freed, not counting `table` itself.
///
/// # Safety
/// `table` must be a live page-table frame nothing else owns, and the tree must
/// not be the one in `CR3`.
unsafe fn free_level(table: u64, level: u32, borrowed: Option<u64>) -> usize {
    let entries = staros_bootinfo::phys_to_virt(table) as *const u64;
    // The PML4 splits at 256; every lower level is entirely within whichever half
    // its parent was, so only the top level needs the restriction.
    let last = if level == 4 { KERNEL_PML4_FIRST } else { 512 };
    let mut freed = 0usize;

    for slot in 0..last {
        // SAFETY: `entries` is a page-aligned table of 512 `u64` reached through
        // the linear map, and `slot` is in range.
        let entry = unsafe { entries.add(slot).read() };
        if entry & PTE_PRESENT == 0 {
            continue;
        }
        let frame = entry & PTE_ADDR_MASK;
        // A leaf: either a huge page, or any entry at the bottom level.
        let leaf = level == 1 || entry & PTE_HUGE != 0;
        if leaf {
            // The one frame a space may map without owning. Freeing it would give
            // the kernel's clock page to the next task that asks for memory.
            if Some(frame) == borrowed {
                continue;
            }
            mem::free_frame(staros_mm::PhysAddr(frame as usize));
            freed += 1;
            continue;
        }
        // SAFETY: an intermediate entry, so `frame` is a table this space
        // allocated; the contract is forwarded down.
        freed += unsafe { free_level(frame, level - 1, borrowed) };
        mem::free_frame(staros_mm::PhysAddr(frame as usize));
        freed += 1;
    }
    freed
}

/// Whether `entry` would let ring 3 reach the page it names. Used by the audit
/// below; kept separate so the rule is stated once.
const fn reachable_by_user(entry: u64) -> bool {
    entry & PTE_PRESENT != 0 && entry & PTE_USER != 0
}

/// Count the PML4 slots in the kernel half of `root` that ring 3 could walk into.
///
/// Zero, always. It is checked rather than assumed because the failure is
/// invisible: a `PTE_USER` bit set on a kernel PML4 entry does not fault, does not
/// change any kernel behaviour, and does not appear in any log — it simply makes
/// the entire kernel readable from ring 3, and the only thing that ever notices
/// is a program that goes looking.
///
/// # Safety
/// `root` must be a live PML4 frame reachable through the linear map.
#[must_use]
pub unsafe fn user_reachable_kernel_slots(root: u64) -> usize {
    let entries = staros_bootinfo::phys_to_virt(root) as *const u64;
    let mut count = 0;
    for slot in KERNEL_PML4_FIRST..512 {
        // SAFETY: forwarded from this function's contract; `slot` is in range.
        let entry = unsafe { entries.add(slot).read() };
        if reachable_by_user(entry) {
            count += 1;
        }
    }
    count
}
