//! Four-level x86_64 page tables, as logic rather than as a side effect.
//!
//! Both halves of this tree build page tables: the loader builds the ones the
//! kernel is entered on, and the kernel builds the ones it lives on afterwards.
//! They differ in exactly two things — where a table frame comes from, and how a
//! physical address is reached in order to write it — and in nothing else. Those
//! two are the trait [`FrameSource`]; everything above them is here, once.
//!
//! ## Why this is worth a crate of its own
//! A page-table walk is pure logic if memory access is abstracted, and page
//! tables are the subsystem where a wrong bit is least visible. A missing
//! `PRESENT` is a triple fault with nothing printed. A missing `NX` is a kernel
//! that is silently executable everywhere. A permission set on an intermediate
//! entry instead of a leaf is worse still, because it *works* — until the day a
//! mapping below it needs a right the intermediate does not grant.
//!
//! So the tree is built against a `Vec` of fake pages on the host, walked back
//! with [`Mapper::translate`], and checked entry by entry. None of that needs a
//! CPU, and all of it is the part that would otherwise be checked by booting.
//!
//! ## The rule that shapes the code
//! Effective rights are **not** the leaf's rights. Along the walk the CPU takes
//! the *AND* of the write bits, the *AND* of the user bits, and the *OR* of the
//! NX bits. A restrictive intermediate therefore silently overrides every leaf
//! beneath it, and a permissive one never grants anything by itself. That is why
//! intermediates here carry exactly the bits the leaf below them needs and no
//! policy of their own, and why [`Mapper::translate`] returns the *effective*
//! rights rather than the leaf's.

#![cfg_attr(not(test), no_std)]

/// 4 KiB, the granule this crate walks in.
pub const PAGE_SIZE: u64 = 4096;
/// A 2 MiB page: one PD entry with `PS` set.
pub const SIZE_2M: u64 = 2 * 1024 * 1024;
/// A 1 GiB page: one PDPT entry with `PS` set.
pub const SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Entry is present; every other bit is meaningless without it.
pub const PTE_PRESENT: u64 = 1 << 0;
/// Writable.
pub const PTE_WRITE: u64 = 1 << 1;
/// Accessible from ring 3.
pub const PTE_USER: u64 = 1 << 2;
/// Write-through rather than write-back.
pub const PTE_PWT: u64 = 1 << 3;
/// Cache disable.
pub const PTE_PCD: u64 = 1 << 4;
/// Page size: this entry maps a large page rather than pointing at a table.
pub const PTE_HUGE: u64 = 1 << 7;
/// No-execute. Only means that with `EFER.NXE` set; otherwise it is a *reserved*
/// bit and every access through the entry faults.
pub const PTE_NX: u64 = 1 << 63;
/// The physical-address field of an entry.
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Rights for one mapping, kept apart from the raw bits so callers state intent
/// and this crate owns the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights {
    /// Writable.
    pub write: bool,
    /// Executable.
    pub exec: bool,
    /// Reachable from ring 3.
    ///
    /// On aarch64 the kernel and user halves are separated by *hardware*, two
    /// table roots in `TTBR1` and `TTBR0`. Here there is one root, and this bit
    /// is the entire separation. A kernel page that accidentally carries it is
    /// readable by every user process, and nothing reports that.
    pub user: bool,
}

impl Rights {
    /// Read-only, non-executable, supervisor. Rodata — and the right default for
    /// anything whose purpose is not clear.
    pub const RO: Self = Self { write: false, exec: false, user: false };
    /// Read/write, non-executable, supervisor. Data, bss, stacks, the linear map.
    pub const RW: Self = Self { write: true, exec: false, user: false };
    /// Read/execute, supervisor. Text, and nothing else — this is the W^X half
    /// that has no write bit.
    pub const RX: Self = Self { write: false, exec: true, user: false };

    /// The same rights, reachable from ring 3.
    #[must_use]
    pub const fn to_user(self) -> Self {
        Self { user: true, ..self }
    }

    /// Whether these rights are both writable and executable.
    ///
    /// Never legitimate for a mapping this kernel makes. Kept as a predicate so
    /// callers can refuse rather than comment.
    #[must_use]
    pub const fn is_wx(self) -> bool {
        self.write && self.exec
    }

    /// The bits a leaf entry carries for these rights, without the address.
    #[must_use]
    pub const fn leaf_bits(self) -> u64 {
        let mut bits = PTE_PRESENT;
        if self.write {
            bits |= PTE_WRITE;
        }
        if self.user {
            bits |= PTE_USER;
        }
        if !self.exec {
            bits |= PTE_NX;
        }
        bits
    }

    /// Decode the rights an entry grants on its own.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self {
            write: bits & PTE_WRITE != 0,
            exec: bits & PTE_NX == 0,
            user: bits & PTE_USER != 0,
        }
    }

    /// Combine rights the way a walk does: AND the permissions, OR the denials.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            write: self.write && other.write,
            exec: self.exec && other.exec,
            user: self.user && other.user,
        }
    }
}

/// How the CPU may cache what a mapping covers.
///
/// Ordinary RAM is cached; device registers must not be. The distinction is not
/// an optimisation — a cached MMIO write can sit in a write-back line and reach
/// the device late or not at all, and a cached read can return a value the
/// device no longer holds. An interrupt controller programmed through cached
/// mappings works right up until the cache decides otherwise.
///
/// On x86 this is *usually* invisible, which is what makes it dangerous: the MTRRs
/// firmware sets already mark the APIC window uncacheable, so a kernel that never
/// sets these bits works on most machines and fails on the one whose firmware
/// did not bother. Saying it in the page tables costs two bits and removes the
/// dependency on somebody else's configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryType {
    /// Write-back cached. RAM.
    Normal,
    /// Uncached and write-through. Device registers.
    Device,
}

impl MemoryType {
    /// The cache-control bits a leaf entry carries.
    #[must_use]
    pub const fn leaf_bits(self) -> u64 {
        match self {
            Self::Normal => 0,
            Self::Device => PTE_PCD | PTE_PWT,
        }
    }

    /// Read the type back out of an entry.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        if bits & PTE_PCD != 0 {
            Self::Device
        } else {
            Self::Normal
        }
    }
}

/// Why a mapping could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// A virtual address, physical address or length was not page-aligned.
    /// Refused rather than rounded: a rounded mapping either exposes memory the
    /// caller did not ask for or omits memory it did.
    Misaligned,
    /// [`FrameSource::alloc_table`] returned `None`.
    OutOfFrames,
    /// The walk met a large page where it needed a table. Splitting one would be
    /// possible; neither caller needs it, and handling a case that cannot arise
    /// hides the day it does.
    LargePageCollision,
}

impl MapError {
    /// A message naming the failure.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Misaligned => "mapping request is not page-aligned",
            Self::OutOfFrames => "no free frame for a page table",
            Self::LargePageCollision => "mapping collides with an existing large page",
        }
    }
}

/// Where table frames come from, and how they are reached.
///
/// # Safety
/// Implementors must guarantee that:
///
/// * [`alloc_table`](FrameSource::alloc_table) returns a page-aligned physical
///   address of 4 KiB that is **zeroed** and owned by nobody else, or `None`;
/// * [`table`](FrameSource::table) returns a pointer valid for reads and writes
///   of 512 `u64` for any address previously returned by `alloc_table`, or
///   handed to [`Mapper::adopt`].
///
/// A pointer from `table` may be invalidated by a later call to `alloc_table` —
/// this crate re-derives it after every allocation and implementors may rely on
/// that, which is what lets the host tests back the trait with a growable `Vec`.
pub unsafe trait FrameSource {
    /// Take one zeroed 4 KiB frame for use as a page table.
    fn alloc_table(&mut self) -> Option<u64>;

    /// Reach a table frame for reading and writing.
    fn table(&mut self, phys: u64) -> *mut u64;
}

/// What a virtual address resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    /// The physical address it maps to, including the offset within the page.
    pub phys: u64,
    /// The rights **as the walk computes them**, not the leaf's own.
    pub rights: Rights,
    /// Whether the leaf says this may be cached.
    ///
    /// From the leaf alone, unlike the rights: the cache-control bits do not
    /// combine along the walk the way permissions do — the CPU takes them from
    /// the entry that maps the page.
    pub memory_type: MemoryType,
    /// The size of the page that covers it: 4 KiB, 2 MiB or 1 GiB.
    pub page_size: u64,
}

/// A four-level page-table tree being built or inspected.
pub struct Mapper<'a, F: FrameSource> {
    root: u64,
    frames: &'a mut F,
    gib_pages: bool,
}

impl<'a, F: FrameSource> Mapper<'a, F> {
    /// Allocate an empty root table (PML4).
    ///
    /// `gib_pages` says whether the CPU has `PDPE1GB`. It is a parameter rather
    /// than a CPUID call because this crate never touches a CPU — which is what
    /// lets both branches be exercised on the host, instead of only whichever
    /// one the development machine happens to have.
    ///
    /// # Errors
    /// [`MapError::OutOfFrames`] if there is no frame for the root.
    pub fn new(frames: &'a mut F, gib_pages: bool) -> Result<Self, MapError> {
        let root = frames.alloc_table().ok_or(MapError::OutOfFrames)?;
        Ok(Self { root, frames, gib_pages })
    }

    /// Work on an existing tree rooted at `root`.
    pub fn adopt(root: u64, frames: &'a mut F, gib_pages: bool) -> Self {
        Self { root, frames, gib_pages }
    }

    /// Physical address of the root table — the value for `CR3`.
    #[must_use]
    pub const fn root(&self) -> u64 {
        self.root
    }

    /// Whether 1 GiB pages will be used where alignment allows.
    #[must_use]
    pub const fn uses_gib_pages(&self) -> bool {
        self.gib_pages
    }

    /// Map `size` bytes of physical memory at `phys` to `virt` with `rights`.
    ///
    /// Uses the largest page both alignments and the remaining length allow,
    /// down to 4 KiB. Large pages are not an optimisation here so much as a
    /// necessity: 64 GiB of linear map in 4 KiB entries is 128 MiB of tables,
    /// which is more memory than the mapping is worth.
    ///
    /// # Errors
    /// See [`MapError`].
    pub fn map(&mut self, virt: u64, phys: u64, size: u64, rights: Rights) -> Result<(), MapError> {
        self.map_as(virt, phys, size, rights, MemoryType::Normal)
    }

    /// Map device registers: the same walk, with the leaves marked uncacheable.
    ///
    /// Separate from [`Mapper::map`] rather than a flag on [`Rights`], because
    /// this is not a permission. Rights say who may touch the memory; this says
    /// what the CPU may do with the value afterwards, and the two combine in
    /// different ways — permissions along the walk, cacheability at the leaf.
    ///
    /// # Errors
    /// See [`MapError`].
    pub fn map_device(
        &mut self,
        virt: u64,
        phys: u64,
        size: u64,
        rights: Rights,
    ) -> Result<(), MapError> {
        self.map_as(virt, phys, size, rights, MemoryType::Device)
    }

    /// The walk both of the above share.
    ///
    /// # Errors
    /// See [`MapError`].
    pub fn map_as(
        &mut self,
        virt: u64,
        phys: u64,
        size: u64,
        rights: Rights,
        memory_type: MemoryType,
    ) -> Result<(), MapError> {
        if !virt.is_multiple_of(PAGE_SIZE)
            || !phys.is_multiple_of(PAGE_SIZE)
            || !size.is_multiple_of(PAGE_SIZE)
        {
            return Err(MapError::Misaligned);
        }

        let mut done = 0u64;
        while done < size {
            let (v, p, left) = (virt + done, phys + done, size - done);
            let step = if self.gib_pages && fits(v, p, left, SIZE_1G) {
                self.map_leaf(v, p, rights, memory_type, 2)?;
                SIZE_1G
            } else if fits(v, p, left, SIZE_2M) {
                self.map_leaf(v, p, rights, memory_type, 1)?;
                SIZE_2M
            } else {
                self.map_leaf(v, p, rights, memory_type, 0)?;
                PAGE_SIZE
            };
            done += step;
        }
        Ok(())
    }

    /// Resolve `virt`, or `None` if nothing maps it.
    ///
    /// The rights returned are the effective ones: the AND of the write and user
    /// bits and the OR of the NX bits along the whole walk, which is what the CPU
    /// enforces and what a caller checking its own tables actually wants to know.
    pub fn translate(&mut self, virt: u64) -> Option<Translation> {
        let mut table = self.root;
        let mut effective = Rights { write: true, exec: true, user: true };
        for level in (0..=3).rev() {
            let entry = self.read(table, index(virt, level));
            if entry & PTE_PRESENT == 0 {
                return None;
            }
            effective = effective.intersect(Rights::from_bits(entry));
            let leaf = level == 0 || entry & PTE_HUGE != 0;
            if leaf {
                let page_size = level_size(level);
                let base = entry & PTE_ADDR_MASK & !(page_size - 1);
                return Some(Translation {
                    phys: base + (virt & (page_size - 1)),
                    rights: effective,
                    memory_type: MemoryType::from_bits(entry),
                    page_size,
                });
            }
            table = entry & PTE_ADDR_MASK;
        }
        None
    }

    /// Remove the mapping covering `virt`, returning what was there.
    ///
    /// The tables that led to it are left in place: they are four kilobytes each,
    /// they will very likely be needed again by the next mapping in the same
    /// region, and reclaiming them means proving no sibling entry is live, which
    /// is a refcount this crate does not keep. Stated rather than hidden, because
    /// it is the difference between a leak and a design.
    ///
    /// The caller is responsible for invalidating the TLB.
    pub fn unmap(&mut self, virt: u64) -> Option<Translation> {
        let existing = self.translate(virt)?;
        let mut table = self.root;
        for level in (0..=3).rev() {
            let idx = index(virt, level);
            let entry = self.read(table, idx);
            if level == 0 || entry & PTE_HUGE != 0 {
                self.write(table, idx, 0);
                return Some(existing);
            }
            table = entry & PTE_ADDR_MASK;
        }
        None
    }

    /// Install one leaf entry at `level` (0 = 4 KiB, 1 = 2 MiB, 2 = 1 GiB).
    ///
    /// The cache bits go on the leaf and nowhere else. On an intermediate entry
    /// `PCD` and `PWT` describe how the CPU may cache *the table it points at*,
    /// not the pages below it — setting them there would make the page walk
    /// uncached and every mapping under it slow, while leaving the device
    /// mapping itself write-back.
    fn map_leaf(
        &mut self,
        virt: u64,
        phys: u64,
        rights: Rights,
        memory_type: MemoryType,
        level: u32,
    ) -> Result<(), MapError> {
        let mut table = self.root;
        let mut walk = 3u32;
        while walk > level {
            table = self.next_table(table, index(virt, walk), rights)?;
            walk -= 1;
        }
        let huge = if level > 0 { PTE_HUGE } else { 0 };
        let bits = phys | rights.leaf_bits() | memory_type.leaf_bits() | huge;
        self.write(table, index(virt, level), bits);
        Ok(())
    }

    /// Follow `table[idx]` down one level, allocating that level if it is absent
    /// and widening it if it is present but too restrictive.
    ///
    /// The widening is the subtle half. Rights are ANDed along the walk, so an
    /// intermediate created earlier for a read-only supervisor mapping would
    /// silently strip `write` and `user` from every mapping later placed beneath
    /// it — and the result is a working kernel that faults the first time a
    /// process touches its own stack.
    fn next_table(&mut self, table: u64, idx: usize, needed: Rights) -> Result<u64, MapError> {
        let entry = self.read(table, idx);
        if entry & PTE_PRESENT != 0 {
            if entry & PTE_HUGE != 0 {
                return Err(MapError::LargePageCollision);
            }
            let widened = entry | intermediate_bits(needed);
            if widened != entry {
                self.write(table, idx, widened);
            }
            return Ok(entry & PTE_ADDR_MASK);
        }
        let page = self.frames.alloc_table().ok_or(MapError::OutOfFrames)?;
        // Re-derived after the allocation on purpose: see the trait contract.
        self.write(table, idx, page | intermediate_bits(needed));
        Ok(page)
    }

    fn read(&mut self, table: u64, idx: usize) -> u64 {
        let ptr = self.frames.table(table);
        // SAFETY: the `FrameSource` contract makes `ptr` valid for 512 `u64`, and
        // `index` cannot return more than 511.
        unsafe { ptr.add(idx).read() }
    }

    fn write(&mut self, table: u64, idx: usize, value: u64) {
        let ptr = self.frames.table(table);
        // SAFETY: as `read`.
        unsafe { ptr.add(idx).write(value) };
    }
}

/// The bits an intermediate entry needs so it does not restrict the leaf below.
///
/// Present and writable always: a read-only intermediate would make everything
/// under it read-only. `USER` only when the leaf is a user mapping, because that
/// bit is the whole kernel/user separation on this architecture and handing it
/// out by default would mean every kernel page sat under a user-accessible
/// branch. NX is never set here — it ORs downwards, and would make the entire
/// subtree non-executable.
const fn intermediate_bits(needed: Rights) -> u64 {
    let mut bits = PTE_PRESENT | PTE_WRITE;
    if needed.user {
        bits |= PTE_USER;
    }
    bits
}

/// Whether a page of `size` can be placed here.
const fn fits(virt: u64, phys: u64, left: u64, size: u64) -> bool {
    virt.is_multiple_of(size) && phys.is_multiple_of(size) && left >= size
}

/// The size of a page whose leaf entry sits at `level`.
const fn level_size(level: u32) -> u64 {
    match level {
        0 => PAGE_SIZE,
        1 => SIZE_2M,
        _ => SIZE_1G,
    }
}

/// The index into the level-`level` table for `virt` (3 = PML4 … 0 = PT).
#[must_use]
pub const fn index(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * level)) & 0x1FF) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Physical memory made of whole pages, addressed from an arbitrary base so
    /// a test cannot pass by treating a physical address as an index.
    struct FakeMemory {
        base: u64,
        pages: Vec<[u64; 512]>,
    }

    impl FakeMemory {
        fn new() -> Self {
            Self { base: 0x1_0000_0000, pages: Vec::new() }
        }
        fn tables(&self) -> usize {
            self.pages.len()
        }
    }

    // SAFETY: `alloc_table` hands out a distinct zeroed page each time, and
    // `table` resolves an address it previously returned. The `Vec` may move its
    // contents on growth, which is exactly the invalidation the trait's contract
    // permits and the crate is written to tolerate.
    unsafe impl FrameSource for FakeMemory {
        fn alloc_table(&mut self) -> Option<u64> {
            self.pages.push([0u64; 512]);
            Some(self.base + (self.pages.len() as u64 - 1) * PAGE_SIZE)
        }
        fn table(&mut self, phys: u64) -> *mut u64 {
            let idx = ((phys - self.base) / PAGE_SIZE) as usize;
            self.pages[idx].as_mut_ptr()
        }
    }

    const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;
    const LINEAR: u64 = 0xFFFF_8000_0000_0000;

    #[test]
    fn a_mapped_page_resolves_to_the_frame_it_was_given() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map(KERNEL_VMA, 0x20_0000, PAGE_SIZE, Rights::RX).unwrap();

        let t = m.translate(KERNEL_VMA).unwrap();
        assert_eq!(t.phys, 0x20_0000);
        assert_eq!(t.page_size, PAGE_SIZE);
        assert_eq!(t.rights, Rights::RX);
        // The offset within the page has to survive the walk.
        assert_eq!(m.translate(KERNEL_VMA + 0xABC).unwrap().phys, 0x20_0ABC);
    }

    #[test]
    fn nothing_else_becomes_mapped_by_accident() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map(KERNEL_VMA, 0x20_0000, PAGE_SIZE, Rights::RW).unwrap();

        // The page before, the page after, and the two addresses this kernel
        // most needs to stay unmapped.
        assert!(m.translate(KERNEL_VMA - PAGE_SIZE).is_none());
        assert!(m.translate(KERNEL_VMA + PAGE_SIZE).is_none());
        assert!(m.translate(0).is_none(), "address zero must not be mapped");
        assert!(m.translate(LINEAR).is_none());
    }

    #[test]
    fn the_largest_page_that_fits_is_the_one_used() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, true).unwrap();

        m.map(LINEAR, 0, 4 * SIZE_1G, Rights::RW).unwrap();
        assert_eq!(m.translate(LINEAR + SIZE_1G + 7).unwrap().page_size, SIZE_1G);
        // Root, PML4->PDPT: two tables for 4 GiB. That is the whole point of
        // 1 GiB pages, so it is asserted rather than assumed.
        assert_eq!(mem.tables(), 2);
    }

    #[test]
    fn without_pdpe1gb_the_same_span_falls_back_to_2_mib() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map(LINEAR, 0, 2 * SIZE_1G, Rights::RW).unwrap();

        assert_eq!(m.translate(LINEAR + SIZE_1G).unwrap().page_size, SIZE_2M);
        assert_eq!(m.translate(LINEAR + SIZE_1G).unwrap().phys, SIZE_1G);
        // Root + PDPT + two PDs. Still bounded, which is why the fallback is
        // acceptable at all.
        assert_eq!(mem.tables(), 4);
    }

    #[test]
    fn a_misaligned_span_degrades_only_where_it_has_to() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, true).unwrap();
        // Starts one page into a 2 MiB block and runs past a 1 GiB boundary.
        m.map(LINEAR + PAGE_SIZE, PAGE_SIZE, SIZE_1G, Rights::RW).unwrap();

        assert_eq!(m.translate(LINEAR + PAGE_SIZE).unwrap().page_size, PAGE_SIZE);
        assert_eq!(m.translate(LINEAR + SIZE_2M).unwrap().page_size, SIZE_2M);
        // Every byte of the requested span is mapped, at the right frame.
        for off in (0..SIZE_1G).step_by(0x4_0000) {
            let t = m.translate(LINEAR + PAGE_SIZE + off).expect("hole in the mapping");
            assert_eq!(t.phys, PAGE_SIZE + off);
        }
        assert!(m.translate(LINEAR).is_none(), "mapped a page that was not asked for");
        assert!(m.translate(LINEAR + PAGE_SIZE + SIZE_1G).is_none(), "ran past the request");
    }

    #[test]
    fn effective_rights_are_the_walk_not_the_leaf() {
        // This is the bug the crate exists to make impossible: rights set on an
        // intermediate override every leaf below it, and the failure is silent.
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();

        // A read-only text page first, then a writable data page in the *same*
        // 2 MiB block, so both share a PT and every table above it.
        m.map(KERNEL_VMA, 0x10_0000, PAGE_SIZE, Rights::RX).unwrap();
        m.map(KERNEL_VMA + PAGE_SIZE, 0x10_1000, PAGE_SIZE, Rights::RW).unwrap();

        assert_eq!(m.translate(KERNEL_VMA).unwrap().rights, Rights::RX);
        let data = m.translate(KERNEL_VMA + PAGE_SIZE).unwrap().rights;
        assert!(data.write, "the read-only text mapping made its own data read-only");
        assert!(!data.exec, "data came out executable");
    }

    #[test]
    fn a_user_leaf_widens_the_supervisor_branch_it_lands_under() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        // A kernel page first, forcing supervisor-only intermediates...
        m.map(0x40_0000, 0x40_0000, PAGE_SIZE, Rights::RW).unwrap();
        // ...then a user page underneath the very same tables.
        m.map(0x40_1000, 0x40_1000, PAGE_SIZE, Rights::RW.to_user()).unwrap();

        assert!(m.translate(0x40_1000).unwrap().rights.user, "user bit lost on the walk");
        // And the kernel page must not have become user-accessible in the
        // process: the U/S bit is the entire kernel/user split here.
        assert!(!m.translate(0x40_0000).unwrap().rights.user);
    }

    #[test]
    fn kernel_mappings_never_carry_the_user_bit() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, true).unwrap();
        m.map(LINEAR, 0, SIZE_1G, Rights::RW).unwrap();
        m.map(KERNEL_VMA, 0x10_0000, SIZE_2M, Rights::RX).unwrap();

        for addr in [LINEAR, LINEAR + 0x1234, KERNEL_VMA, KERNEL_VMA + 0x1000] {
            assert!(!m.translate(addr).unwrap().rights.user, "{addr:#x} is user-accessible");
        }
    }

    #[test]
    fn w_and_x_are_never_granted_together_by_this_crate() {
        // Not enforced by `map` — a caller may ask for it — but every set of
        // rights this crate offers as a constant must be one or the other.
        for r in [Rights::RO, Rights::RW, Rights::RX] {
            assert!(!r.is_wx());
            assert!(!r.to_user().is_wx());
        }
    }

    #[test]
    fn a_mapping_can_be_replaced_but_not_punched_through_a_large_page() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map(LINEAR, 0, SIZE_2M, Rights::RW).unwrap();
        assert_eq!(m.translate(LINEAR).unwrap().page_size, SIZE_2M);

        // A 4 KiB mapping inside it needs a PT where a 2 MiB leaf already sits.
        assert_eq!(
            m.map(LINEAR, 0, PAGE_SIZE, Rights::RO),
            Err(MapError::LargePageCollision),
        );
        // Replacing the whole large page is fine, and takes effect.
        m.map(LINEAR, 0x40_0000, SIZE_2M, Rights::RO).unwrap();
        let t = m.translate(LINEAR).unwrap();
        assert_eq!((t.phys, t.rights), (0x40_0000, Rights::RO));
    }

    #[test]
    fn unmapping_removes_exactly_one_mapping() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map(0x40_0000, 0x8_0000, 3 * PAGE_SIZE, Rights::RW.to_user()).unwrap();

        let gone = m.unmap(0x40_1000).expect("nothing was mapped there");
        assert_eq!(gone.phys, 0x8_1000);
        assert!(gone.rights.user);
        assert!(m.translate(0x40_1000).is_none());
        // The neighbours, which share every table with it, must be untouched.
        assert_eq!(m.translate(0x40_0000).unwrap().phys, 0x8_0000);
        assert_eq!(m.translate(0x40_2000).unwrap().phys, 0x8_2000);
        // And unmapping nothing says so rather than corrupting a table.
        assert_eq!(m.unmap(0x40_1000), None);
    }

    #[test]
    fn a_large_page_is_unmapped_whole() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, true).unwrap();
        m.map(LINEAR, 0, SIZE_1G, Rights::RW).unwrap();
        assert_eq!(m.unmap(LINEAR + 0x1234).unwrap().page_size, SIZE_1G);
        assert!(m.translate(LINEAR).is_none());
        assert!(m.translate(LINEAR + SIZE_1G - PAGE_SIZE).is_none());
    }

    #[test]
    fn device_mappings_are_uncached_and_ram_is_not() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map(LINEAR, 0, PAGE_SIZE, Rights::RW).unwrap();
        m.map_device(LINEAR + PAGE_SIZE, 0xFEE0_0000, PAGE_SIZE, Rights::RW).unwrap();

        assert_eq!(m.translate(LINEAR).unwrap().memory_type, MemoryType::Normal);
        let dev = m.translate(LINEAR + PAGE_SIZE).unwrap();
        assert_eq!(dev.memory_type, MemoryType::Device);
        assert_eq!(dev.phys, 0xFEE0_0000);
        // Rights are unaffected: this is not a permission.
        assert_eq!(dev.rights, Rights::RW);
    }

    #[test]
    fn the_cache_bits_are_the_two_the_architecture_names() {
        assert_eq!(MemoryType::Normal.leaf_bits(), 0);
        assert_eq!(MemoryType::Device.leaf_bits(), PTE_PCD | PTE_PWT);
        assert_eq!(PTE_PWT, 1 << 3);
        assert_eq!(PTE_PCD, 1 << 4);
        // And they must not collide with anything else a leaf carries. PWT and
        // PCD sit between the user bit and the accessed bit, which is exactly
        // the sort of neighbourhood an off-by-one lands in.
        for r in [Rights::RO, Rights::RW, Rights::RX, Rights::RW.to_user()] {
            assert_eq!(r.leaf_bits() & (PTE_PCD | PTE_PWT), 0);
        }
    }

    #[test]
    fn cacheability_comes_from_the_leaf_not_the_walk() {
        // Unlike permissions. A device page and a RAM page can share every table
        // above them, and each must keep its own answer - if the bits were
        // combined along the walk the way rights are, one would take the other's.
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map_device(LINEAR, 0xFEC0_0000, PAGE_SIZE, Rights::RW).unwrap();
        m.map(LINEAR + PAGE_SIZE, 0x1000, PAGE_SIZE, Rights::RW).unwrap();

        assert_eq!(m.translate(LINEAR).unwrap().memory_type, MemoryType::Device);
        assert_eq!(m.translate(LINEAR + PAGE_SIZE).unwrap().memory_type, MemoryType::Normal);
    }

    #[test]
    fn a_device_mapping_can_use_a_large_page() {
        // Some device windows are megabytes wide, and the leaf that carries the
        // cache bits is then a PD entry rather than a PT entry.
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        m.map_device(LINEAR, 0xE000_0000, SIZE_2M, Rights::RW).unwrap();
        let t = m.translate(LINEAR + 0x1000).unwrap();
        assert_eq!(t.page_size, SIZE_2M);
        assert_eq!(t.memory_type, MemoryType::Device);
    }

    #[test]
    fn misaligned_requests_are_refused_rather_than_rounded() {
        let mut mem = FakeMemory::new();
        let mut m = Mapper::new(&mut mem, false).unwrap();
        assert_eq!(m.map(1, 0, PAGE_SIZE, Rights::RW), Err(MapError::Misaligned));
        assert_eq!(m.map(0, 1, PAGE_SIZE, Rights::RW), Err(MapError::Misaligned));
        assert_eq!(m.map(0, 0, 1, Rights::RW), Err(MapError::Misaligned));
        // And nothing was written on the way to refusing.
        assert!(m.translate(0).is_none());
    }

    #[test]
    fn running_out_of_frames_is_reported_not_ignored() {
        struct Empty(u32);
        // SAFETY: hands out one frame then nothing; `table` is only ever called
        // for that one.
        unsafe impl FrameSource for Empty {
            fn alloc_table(&mut self) -> Option<u64> {
                self.0 = self.0.checked_sub(1)?;
                Some(0x1000)
            }
            fn table(&mut self, _phys: u64) -> *mut u64 {
                static mut PAGE: [u64; 512] = [0; 512];
                &raw mut PAGE as *mut u64
            }
        }
        let mut mem = Empty(1);
        let mut m = Mapper::new(&mut mem, false).unwrap();
        assert_eq!(m.map(KERNEL_VMA, 0, PAGE_SIZE, Rights::RX), Err(MapError::OutOfFrames));
    }

    #[test]
    fn indices_split_the_address_the_way_the_cpu_does() {
        // One distinct index per level, so a shifted field is a wrong value.
        let virt = (1u64 << 39) | (2 << 30) | (3 << 21) | (4 << 12) | 0x567;
        assert_eq!(index(virt, 3), 1);
        assert_eq!(index(virt, 2), 2);
        assert_eq!(index(virt, 1), 3);
        assert_eq!(index(virt, 0), 4);
        // The top half: PML4 index 511 is where the kernel lives.
        assert_eq!(index(KERNEL_VMA, 3), 511);
        assert_eq!(index(LINEAR, 3), 256);
    }

    #[test]
    fn leaf_bits_round_trip_and_nx_is_the_top_bit() {
        for r in [Rights::RO, Rights::RW, Rights::RX, Rights::RW.to_user()] {
            assert_eq!(Rights::from_bits(r.leaf_bits()), r);
            assert_ne!(r.leaf_bits() & PTE_PRESENT, 0);
        }
        // NX is bit 63 and is *set* to forbid execution — the inverted sense is
        // the classic mistake, and it fails open.
        assert_eq!(Rights::RX.leaf_bits() & PTE_NX, 0);
        assert_eq!(Rights::RW.leaf_bits() & PTE_NX, PTE_NX);
    }
}
