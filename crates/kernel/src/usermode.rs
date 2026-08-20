//! Ring 3: the program, the spaces it runs in, and the syscalls it makes.
//!
//! The policy half of phases 3.1 and 3.2. [`staros_arch_x86_64::syscall`] and
//! [`staros_arch_x86_64::usermode`] own the transitions; [`crate::addrspace`]
//! owns the trees; this module decides what ring 3 is allowed to do and proves
//! it can.
//!
//! ## Where the program comes from
//! A real, separately linked x86-64 executable. `services/init/boot/image.rs` is
//! compiled by the kernel's `build.rs` with its own linker script, placed at
//! `USER_BASE` = 0x400000 with a read-execute and a read-write `PT_LOAD` segment,
//! and embedded here with `include_bytes!`. `staros-elf64` — the same parser the
//! UEFI loader uses on the kernel image itself — walks its program headers and
//! [`AddressSpace::load`] maps each segment at its own address with its own
//! rights.
//!
//! Phase 3.1 had a blob assembled into the kernel's `.rodata` and copied into a
//! frame, because there was no per-task tree to load anything into. That is what
//! this replaces, and the difference is not cosmetic: an image the kernel does
//! not assemble is one whose entry point, segment count and rights it has to
//! *read* rather than know.
//!
//! ## Two tasks, one image, two spaces
//! The same executable is loaded twice, into two address spaces, and each is
//! seeded with a different process id byte at [`USER_DATA_VA`] — the same virtual
//! address, a different physical frame. The program branches on that byte:
//!
//! - **id 1** prints, spins in ring 3 until the clock advances, yields once, and
//!   exits cleanly.
//! - **id 2** prints and then dereferences a null pointer.
//!
//! Task 2 must die and task 1 must not notice. That is the phase criterion, and
//! the boot log also prints what [`USER_BASE`] resolves to in each space — two
//! different physical addresses for one virtual address being the shortest
//! statement of what "separate address spaces" means.
//!
//! ## What ring 3 may call
//! `Yield`, `Exit` and `DebugWrite`, out of the twenty numbers
//! [`staros_abi::syscall::Syscall`] defines. Everything else answers
//! [`KError::NoSuchSyscall`]: a syscall that returns a plausible value without
//! doing anything is worse than one that says no.
//!
//! `DebugWrite` takes a **pointer into ring 3's memory**, so the kernel has to
//! answer two questions. Whether the caller may read that address — which is
//! [`AddressSpace::range_ok`], a walk of *that task's* tree, because from phase
//! 3.2 there is no single tree to check against and being in the user half proves
//! nothing anyway. And how ring 0 reads it at all with SMAP on — `stac` around
//! the copy and `clac` after, the only place in this kernel that opens that
//! window.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use staros_abi::error::KError;
use staros_abi::syscall::Syscall;
use staros_abi::Handle;
use staros_arch_x86_64::syscall::{self as arch_syscall, SyscallFrame};
use staros_arch_x86_64::{cpu, usermode};
use staros_elf64::Elf;

use staros_ipc::Message;

use crate::addrspace::{AddressSpace, USER_STACK_TOP};
use crate::cap::Cap;
use crate::console::Console;
use crate::ipc::{self, KMessage};
use crate::obj::{self, Object};
use crate::vm::Tables;
use crate::{mem, sched};

/// The ring-3 program, built by `build.rs` and linked at [`USER_BASE`].
static USER_IMAGE: &[u8] = include_bytes!(env!("STAROS_USER_IMAGE"));

/// Where the program's first segment lands. Not chosen here — it is the image's
/// own `p_vaddr`, and this constant exists only so the boot log can name the
/// address it translates in both spaces.
const USER_BASE: u64 = 0x0000_0000_0040_0000;

// How long the surviving task spins in ring 3 is decided by the *program*, not
// by the kernel: thirty ticks, written into `services/init/boot/image.rs`. It is
// user space's own business how long it runs, and a kernel-side constant that had
// to agree with a number in the image would be two statements of one fact.

/// A non-canonical address: bit 47 clear, bits above it set. See
/// [`selftest_noncanonical`].
const NONCANONICAL_RIP: u64 = 0x0000_8000_0000_0000;

/// Longest buffer `DebugWrite` will copy in one call.
///
/// A cap, and a security parameter rather than a convenience: the buffer lands on
/// the kernel stack, and a length ring 3 chooses is a length ring 3 chooses.
/// Without this the syscall is a stack overflow with a user-space trigger.
const DEBUG_WRITE_MAX: usize = 256;

/// Whether `CR4.SMAP` is on, so the copy path knows whether `stac` is an
/// instruction or an invalid opcode. Read from the register at [`init`].
static SMAP_ON: AtomicBool = AtomicBool::new(false);

/// Kernel address of the shared clock page — the linear-map alias, which is how
/// the timer writes to a page every task sees as read-only.
static CLOCK_KERNEL_VA: AtomicUsize = AtomicUsize::new(0);
/// Physical address of the same page, which is what gets mapped into each space.
static CLOCK_FRAME: AtomicU64 = AtomicU64::new(0);

/// `Yield` syscalls served.
///
/// Counted here rather than taken from the scheduler's switch count, because the
/// two are different facts and only this one is about ring 3. By the time the
/// surviving task yields, its neighbour has already faulted and been destroyed —
/// so there is nothing to switch *to*, and the scheduler correctly declines.
/// A yield that does not switch still went all the way down through `syscall`,
/// into the scheduler, and back out through `sysretq`, which is what this phase
/// needs to know.
static YIELD_CALLS: AtomicU64 = AtomicU64::new(0);

/// Syscalls served, refused, and bytes written.
static SYSCALLS: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);
static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Set when the next syscall's return address should be corrupted.
static ARM_NONCANONICAL: AtomicBool = AtomicBool::new(false);

/// Faults taken in ring 3, which kill a task and nothing else.
static USER_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Objects destroyed by a ring-3 `Revoke` that found them alive.
static REVOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Ring-3 faults so far.
#[must_use]
pub fn user_faults() -> u64 {
    USER_FAULTS.load(Ordering::Relaxed)
}

/// Record that a fault arrived from ring 3. Called by the trap handler before it
/// destroys the task.
pub fn note_user_fault() {
    USER_FAULTS.fetch_add(1, Ordering::Relaxed);
}

/// Publish the current tick count to the page every ring-3 task reads.
///
/// Called from the timer interrupt, so it is deliberately three instructions and
/// takes no lock. A volatile store rather than an atomic because there is one
/// writer (this core's timer) and one reader (whichever ring-3 program is
/// running), and they are the same core: the store cannot tear, and the reader is
/// a `mov` that sees either the old value or the new one.
pub fn publish_ticks(ticks: u64) {
    let at = CLOCK_KERNEL_VA.load(Ordering::Relaxed);
    if at == 0 {
        return;
    }
    // SAFETY: `at` is the linear-map alias of a frame this module allocated and
    // owns, written only here. The linear map is live for the life of the kernel
    // and the address is page — therefore 8-byte — aligned.
    unsafe { (at as *mut u64).write_volatile(ticks) };
}

/// Turn `syscall` on and allocate the page every ring-3 task shares.
///
/// # Errors
/// Names what could not be set up. All of them are fatal to the phase.
///
/// # Safety
/// Called once, on the boot core, after `vm::init` and `gdt::install`, with
/// interrupts masked.
pub unsafe fn init(console: &mut Console, tables: &Tables) -> Result<(), &'static str> {
    SMAP_ON.store(tables.smap, Ordering::SeqCst);

    let clock = mem::alloc_frame().ok_or("no frame for the ring-3 clock")?.0 as u64;
    let clock_kernel = staros_bootinfo::phys_to_virt(clock) as *mut u8;
    // SAFETY: a frame just allocated exclusively from the pool and mapped
    // read/write through the linear map.
    unsafe { core::ptr::write_bytes(clock_kernel, 0, staros_paging::PAGE_SIZE as usize) };
    CLOCK_KERNEL_VA.store(clock_kernel as usize, Ordering::SeqCst);
    CLOCK_FRAME.store(clock, Ordering::SeqCst);
    // Seed it before ring 3 can read it. The counter is cumulative from the first
    // tick this kernel ever took, so a page left at zero tells a program it is at
    // time zero, and its "wait thirty ticks" is satisfied by the first tick that
    // arrives — which looks exactly like a working test and reports two
    // preemptions instead of fifteen.
    publish_ticks(crate::irq::ticks());

    // SAFETY: the GDT is installed and holds the selectors `IA32_STAR` names; the
    // handler is registered before anything can call it; nothing is in ring 3.
    unsafe { arch_syscall::init() };
    arch_syscall::set_handler(on_syscall);
    // SAFETY: ring 0.
    if !unsafe { arch_syscall::is_enabled() } {
        return Err("IA32_EFER.SCE did not take: `syscall` is still an invalid opcode");
    }

    let star = arch_syscall::star_value(
        staros_arch_x86_64::gdt::KERNEL_CODE,
        staros_arch_x86_64::gdt::USER_CODE32 & !3,
    );
    let _ = writeln!(
        console,
        "syscall: enabled, entry {:#x}, kernel cs {:#04x}, sysret cs {:#04x} ss {:#04x}, fmask {:#x}",
        // SAFETY: ring 0; a plain MSR read.
        unsafe { cpu::read_msr(arch_syscall::IA32_LSTAR) },
        arch_syscall::syscall_cs(star),
        arch_syscall::sysret_cs(star),
        arch_syscall::sysret_ss(star),
        arch_syscall::FMASK,
    );
    Ok(())
}

/// Build one ring-3 address space around the embedded image, seeded with `id`.
///
/// # Errors
/// Names the ELF or allocation problem that stopped it.
fn build_space(tables: &Tables, id: u8) -> Result<AddressSpace, &'static str> {
    let image = Elf::parse(USER_IMAGE).map_err(staros_elf64::ElfError::as_str)?;
    let mut space = AddressSpace::new(tables)?;
    space.load(&image)?;
    space.map_stack()?;
    space.seed_id(id)?;
    space.map_clock(CLOCK_FRAME.load(Ordering::SeqCst))?;
    Ok(space)
}

/// The task body for a ring-3 program: drop into it and never come back.
///
/// A kernel thread whose whole job is one instruction. Its address space, kernel
/// stack and `TSS.rsp0` were all installed by the scheduler when it switched
/// here; this function's own frame is abandoned the moment `iretq` runs, which is
/// correct — a task in ring 3 has an empty kernel stack by definition, and every
/// way back in starts at the top of it.
extern "C" fn user_task() {
    let Some(space) = sched::current_space() else {
        // A user trampoline with no space is a spawn that went through the wrong
        // door. There is nothing to enter.
        sched::exit()
    };
    // SAFETY: the space was loaded from a validated ELF with an executable
    // segment at its entry point and a writable stack below `USER_STACK_TOP`, it
    // is the tree in `CR3` (the scheduler put it there), the IDT is installed,
    // `syscall` is enabled with a handler, and `TSS.rsp0` holds this task's
    // kernel stack.
    unsafe { usermode::enter_ring3(space.entry(), USER_STACK_TOP) }
}

/// Every syscall arrives here.
fn on_syscall(frame: &mut SyscallFrame) {
    SYSCALLS.fetch_add(1, Ordering::Relaxed);

    // Armed before the call is served and consumed here, so the corruption lands
    // on a return the program would otherwise have made successfully.
    let corrupt = ARM_NONCANONICAL.swap(false, Ordering::SeqCst);

    match Syscall::from_raw(frame.rax as usize) {
        Some(Syscall::Yield) => {
            YIELD_CALLS.fetch_add(1, Ordering::Relaxed);
            frame.rax = 0;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
            // `GS` belongs to the core, not to this task, so it has to be put
            // back the way ordinary ring-0 code expects before anything else
            // runs. See `arch_syscall::swap_gs`.
            // SAFETY: ring 0, inside the syscall path, paired with the call below.
            unsafe { arch_syscall::swap_gs() };
            sched::yield_now();
            // SAFETY: the pairing. This task is back on the CPU and about to
            // return through the stub, which expects the kernel base in `GS`.
            unsafe { arch_syscall::swap_gs() };
        }
        Some(Syscall::Exit) => {
            // Never returns, and never writes `rax`: nobody is left to read it.
            // The unpaired half of the stub's `swapgs` is exactly why this call is
            // here — the stub's exit path is what would have restored `GS`, and
            // this task will never reach it.
            // SAFETY: ring 0, inside the syscall path.
            unsafe { arch_syscall::swap_gs() };
            sched::exit()
        }
        Some(Syscall::DebugWrite) => {
            frame.rax = debug_write(frame.rdi, frame.rsi);
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
        // The three phase-3.3 calls. Each of them can block — `Send` on a full
        // ring, `Recv` on an empty one — which is why `GS` is put back the way
        // ring-0 code expects around them, exactly as `Yield` does: a switch in
        // the middle leaves this core running somebody else's code, and the
        // kernel base in `GS` would be waiting there for the next syscall from
        // any task to swap it into the user's.
        Some(Syscall::Send) => {
            // SAFETY: ring 0, inside the syscall path, paired with the call below.
            unsafe { arch_syscall::swap_gs() };
            let rc = sys_send(frame.rdi as u32, frame.rsi);
            // SAFETY: the pairing. Back on this core, about to return through the
            // stub, which expects the kernel base in `GS`.
            unsafe { arch_syscall::swap_gs() };
            frame.rax = rc as u64;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
        Some(Syscall::Recv) => {
            // SAFETY: as `Send` above.
            unsafe { arch_syscall::swap_gs() };
            let rc = sys_recv(frame.rdi as u32, frame.rsi);
            // SAFETY: the pairing.
            unsafe { arch_syscall::swap_gs() };
            frame.rax = rc as u64;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
        Some(Syscall::Revoke) => {
            frame.rax = sys_revoke(frame.rdi as u32) as u64;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
        _ => {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            frame.rax = KError::NoSuchSyscall.as_raw() as u64;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
    }
}

/// `DebugWrite`: emit `len` bytes from ring 3's `ptr` as one console message.
///
/// Returns the number of bytes written, or a negative [`KError`] as a raw `u64` —
/// which is what the ABI says a syscall result is.
fn debug_write(ptr: u64, len: u64) -> u64 {
    let Ok(len) = usize::try_from(len) else {
        return KError::InvalidArgument.as_raw() as u64;
    };
    if len > DEBUG_WRITE_MAX {
        return KError::InvalidArgument.as_raw() as u64;
    }

    // The *caller's* tree, not a global one. From phase 3.2 there is no single
    // user address space to check against, and checking against the wrong one
    // would accept an address that is mapped for somebody else.
    let Some(space) = sched::current_space() else {
        return KError::NotSupported.as_raw() as u64;
    };
    if !space.range_ok(ptr, len as u64, false) {
        return KError::InvalidArgument.as_raw() as u64;
    }

    let mut buffer = [0u8; DEBUG_WRITE_MAX];
    let smap = SMAP_ON.load(Ordering::Relaxed);
    // The one place in this kernel that opens the SMAP window. `stac` sets
    // `RFLAGS.AC`, suspending SMAP for supervisor accesses to user pages; `clac`
    // closes it. The window is exactly as wide as the copy.
    //
    // Conditional, and not as an optimisation: on a CPU without SMAP `stac` is
    // not a no-op but `#UD`. `qemu64` is such a CPU, which is why it is in the
    // boot matrix — the feature the kernel checked for in phase 1.4 and the
    // instruction it uses here are the same fact.
    //
    // SAFETY: the range has just been verified mapped and user-readable in the
    // caller's live tree, `len <= DEBUG_WRITE_MAX` bounds the destination, and
    // the two regions cannot overlap (one is a user address, the other this
    // frame's stack). `AC` is cleared again immediately, and neither instruction
    // is issued on a machine without SMAP.
    unsafe {
        if smap {
            cpu::stac();
        }
        core::ptr::copy_nonoverlapping(ptr as *const u8, buffer.as_mut_ptr(), len);
        if smap {
            cpu::clac();
        }
    }

    match core::str::from_utf8(&buffer[..len]) {
        Ok(text) => {
            // One `write_str`, so the console lock is held once for the whole of
            // the caller's message — the same guarantee kernel code gets.
            if let Some(mut console) = crate::console::get() {
                let _ = console.write_str(text);
            }
            BYTES_WRITTEN.fetch_add(len as u64, Ordering::Relaxed);
            len as u64
        }
        // Not fatal, and not silently mangled either: the console draws bytes, and
        // a program that hands it a broken sequence should be told so rather than
        // watch half its line appear.
        Err(_) => KError::InvalidArgument.as_raw() as u64,
    }
}

// ---------------------------------------------------------------------------
// Phase 3.3: IPC, capabilities and revocation.
// ---------------------------------------------------------------------------

/// Copy a [`Message`] out of ring 3's memory.
///
/// Two checks before the copy and neither is optional. The address must be
/// mapped and user-readable *in the caller's own tree* — being in the user half
/// proves nothing since 3.2, and a walk is the only way to know. And it must be
/// eight-byte aligned, because the struct is `u64`-aligned and a misaligned
/// `read_unaligned` here would be papering over a caller whose pointer arithmetic
/// is wrong.
fn read_user_msg(ptr: u64) -> Option<Message> {
    let len = core::mem::size_of::<Message>() as u64;
    if !ptr.is_multiple_of(8) {
        return None;
    }
    let space = sched::current_space()?;
    if !space.range_ok(ptr, len, false) {
        return None;
    }
    let mut msg = Message::new(0);
    // SAFETY: the range is mapped and user-readable in the live tree, the
    // destination is a whole `Message` on this frame's stack, and the two regions
    // cannot overlap. The SMAP window is exactly as wide as the copy; `stac` is
    // issued only on a CPU that has SMAP, since elsewhere it is `#UD`.
    unsafe {
        let smap = SMAP_ON.load(Ordering::Relaxed);
        if smap {
            cpu::stac();
        }
        core::ptr::copy_nonoverlapping(
            ptr as *const u8,
            (&raw mut msg).cast::<u8>(),
            len as usize,
        );
        if smap {
            cpu::clac();
        }
    }
    Some(msg)
}

/// Copy a [`Message`] into ring 3's memory. The write counterpart of
/// [`read_user_msg`], and the `true` in `range_ok` is the whole difference: a
/// receive buffer in a read-only page is a program that would silently never see
/// its message.
fn write_user_msg(ptr: u64, msg: Message) -> bool {
    let len = core::mem::size_of::<Message>() as u64;
    if !ptr.is_multiple_of(8) {
        return false;
    }
    let Some(space) = sched::current_space() else {
        return false;
    };
    if !space.range_ok(ptr, len, true) {
        return false;
    }
    // SAFETY: as `read_user_msg`, with the range verified writable.
    unsafe {
        let smap = SMAP_ON.load(Ordering::Relaxed);
        if smap {
            cpu::stac();
        }
        core::ptr::copy_nonoverlapping(
            (&raw const msg).cast::<u8>(),
            ptr as *mut u8,
            len as usize,
        );
        if smap {
            cpu::clac();
        }
    }
    true
}

/// Resolve `handle` to the endpoint id it names, checking both the right the
/// caller holds and whether the object still exists.
///
/// Those are two different failures and they answer differently on purpose. A
/// handle naming a capability without the direction asked for is
/// [`KError::PermissionDenied`] — the holder has *something*, just not this. A
/// handle whose object has been revoked is [`KError::BadHandle`], the same answer
/// as a handle that never existed, because from the holder's side there is no
/// difference: the authority is gone.
fn endpoint_for(handle: u32, want_send: bool) -> Result<usize, KError> {
    match sched::resolve_cap(handle) {
        Some(Cap::Endpoint { obj, send, recv }) => {
            if (want_send && !send) || (!want_send && !recv) {
                return Err(KError::PermissionDenied);
            }
            match obj::get(obj) {
                Some(Object::Endpoint { id }) => Ok(id),
                None => Err(KError::BadHandle),
            }
        }
        None => Err(KError::BadHandle),
    }
}

/// `Send`: `RDI` = an endpoint handle, `RSI` = a pointer to the caller's
/// [`Message`].
///
/// A message may carry one of the caller's own capabilities, named by
/// `Message.cap`. The kernel resolves it *here*, in the sender's table, and
/// carries the resolved capability — a handle is an index into one task's table
/// and means nothing in another's, so passing the number would hand the receiver
/// whatever happened to sit at that index in its own.
fn sys_send(handle: u32, msg_ptr: u64) -> isize {
    let id = match endpoint_for(handle, true) {
        Ok(id) => id,
        Err(e) => {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            return e.as_raw();
        }
    };
    let Some(msg) = read_user_msg(msg_ptr) else {
        return KError::InvalidArgument.as_raw();
    };
    let cap = if msg.cap.is_null() {
        None
    } else {
        match sched::resolve_cap(msg.cap.0) {
            Some(c) => Some(c),
            None => return KError::BadHandle.as_raw(),
        }
    };
    ipc::send(id, KMessage { msg, cap })
}

/// `Recv`: `RDI` = an endpoint handle, `RSI` = a pointer to a [`Message`] to
/// fill. Blocks until something arrives.
///
/// A transferred capability is installed into *this* task's table and the fresh
/// handle written into the message the caller reads back. The receiver therefore
/// learns the handle the same way it learns the payload, which is the only way it
/// could: the sender never knew it.
fn sys_recv(handle: u32, msg_ptr: u64) -> isize {
    let id = match endpoint_for(handle, false) {
        Ok(id) => id,
        Err(e) => {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            return e.as_raw();
        }
    };
    // Check the destination *before* blocking. A receiver parked on an endpoint
    // with an unwritable buffer consumes a message and then discards it, and the
    // sender has no way to find out.
    if !write_user_msg(msg_ptr, Message::new(0)) {
        return KError::InvalidArgument.as_raw();
    }
    let km = match ipc::recv(id) {
        Ok(km) => km,
        Err(e) => return e.as_raw(),
    };
    let mut msg = km.msg;
    msg.cap = match km.cap {
        Some(cap) => match sched::install_cap_current(cap) {
            Some(h) => Handle(h),
            None => return KError::OutOfResources.as_raw(),
        },
        None => Handle::NULL,
    };
    if write_user_msg(msg_ptr, msg) {
        0
    } else {
        KError::InvalidArgument.as_raw()
    }
}

/// `Revoke`: `RDI` = a handle. Destroys the *object* it names, for everyone.
///
/// Not a slot drop. The caller's handle keeps resolving to a capability; what
/// stops resolving is the capability's reference into the object table — in this
/// task and in every other, including copies delegated over IPC minutes earlier.
/// That is the whole reason a capability holds an [`ObjectRef`](crate::obj) and
/// not the object.
fn sys_revoke(handle: u32) -> isize {
    match sched::resolve_cap(handle) {
        Some(cap) => {
            if obj::revoke(cap.object()) {
                REVOCATIONS.fetch_add(1, Ordering::Relaxed);
                0
            } else {
                // Already revoked, by this task or another. Idempotent rather than
                // an event, so a doubled revoke is not a second story.
                KError::BadHandle.as_raw()
            }
        }
        None => KError::BadHandle.as_raw(),
    }
}

/// The ids the phase-3.3 roles run under, in spawn order. The program branches
/// on the id byte the kernel seeds, exactly as 3.2's two tasks do.
const ROLE_SERVER: u8 = 3;
const ROLE_CLIENT: u8 = 4;
const ROLE_SENDERS: [u8; 3] = [5, 6, 7];
const ROLE_SINK: u8 = 8;

/// Messages that must cross an endpoint during [`selftest_ipc`], counted from the
/// protocol the program implements: three requests, two replies, one message
/// through the delegated capability, and forty-eight from the storm.
///
/// An exact number rather than a floor, and the two refused sends are
/// deliberately not in it — they never reach [`ipc::send`], because the handle
/// stops resolving one layer above. A count that included them would still pass
/// if revocation quietly let one through.
const EXPECTED_MESSAGES: u64 = 3 + 2 + 1 + 48;

/// Sends that must have had to wait for a ring slot, **per endpoint**: the
/// client's third request, and at least one from each storm sender.
///
/// Floors rather than exact numbers, because how often the three senders block
/// depends on when the timer preempts them — but *that* they block is fixed by
/// the arithmetic: two ring slots, three senders, and a sink that stays away for
/// five ticks before its first receive.
///
/// Per endpoint, because a total is a check that does not check. Widening the
/// ring to eight slots leaves the storm blocking seven times, so a total-only
/// floor of four still passes while the client — whose line in the boot log says
/// its third request waited — never waits for anything.
const MIN_REQUEST_BLOCKS: u64 = 1;
const MIN_STORM_BLOCKS: u64 = 3;

/// Phase 3.3: six programs, four endpoints, one delegated capability and one
/// revocation.
///
/// The claims this run establishes, each of which fails loudly rather than
/// quietly:
///
/// - **messages cross address spaces** — six ring-3 tasks in six private trees
///   exchange fifty-four messages that exist, in between, only inside the kernel.
/// - **rights are per direction** — every endpoint capability grants send or
///   receive, not both, and the roles are built from that asymmetry.
/// - **a full ring blocks the sender** — three requests into two slots, and
///   dozens more in the storm; the sender parks inside the syscall and cannot
///   tell it did.
/// - **order is preserved per sender** — three senders interleave arbitrarily,
///   but each one's own sequence arrives in the order it was sent, and the sink
///   checks both the ordering and the exact sum.
/// - **capabilities are delegated, not guessed** — the client is granted no
///   access to the endpoint it ends up using; the authority arrives inside a
///   message and the kernel allocates the handle it lands under.
/// - **revocation is global** — the server destroys the object, and the client's
///   handle, minted by the kernel and never touched since, stops resolving.
///   So does the server's own second handle to the same object.
/// - **nothing is left waiting** — no task is still blocked at the end, and every
///   frame the six spaces owned came back.
///
/// # Safety
/// Called once, after [`selftest`], with the timer calibrated.
pub unsafe fn selftest_ipc(console: &mut Console, tables: &Tables) -> bool {
    let before = mem::frames_in_use();

    // The four endpoints, and the objects that name them. `obj::create` refuses
    // an id past the end of the endpoint table, so a mismatch between these
    // constants and `ipc::NUM_ENDPOINTS` fails here rather than inside a server.
    let mut refs = [None; 4];
    for (slot, id) in refs.iter_mut().zip([
        ipc::REQUEST_EP,
        ipc::REPLY_EP,
        ipc::DELEGATED_EP,
        ipc::STORM_EP,
    ]) {
        match obj::create(Object::Endpoint { id }) {
            Some(r) => *slot = Some(r),
            None => {
                let _ = writeln!(console, "ipc SELF-TEST FAILED: no object for endpoint {id}");
                return false;
            }
        }
    }
    let [Some(request), Some(reply), Some(delegated), Some(storm)] = refs else {
        let _ = writeln!(console, "ipc SELF-TEST FAILED: an endpoint object went missing");
        return false;
    };

    let send_on = |obj| Cap::Endpoint {
        obj,
        send: true,
        recv: false,
    };
    let recv_on = |obj| Cap::Endpoint {
        obj,
        send: false,
        recv: true,
    };

    // Handle numbers are not chosen here — they fall out of the order of these
    // grants, bottom-up from 1, and the program knows them by that order. The
    // server gets *two* capabilities on the delegated endpoint, receive and send,
    // because it keeps the first and gives the second away: one capability with
    // both rights would have handed the client the right to steal its own
    // requests.
    let roles: [(u8, &'static str, &[Cap]); 6] = [
        (
            ROLE_SERVER,
            "SRV",
            &[
                recv_on(request),
                send_on(reply),
                recv_on(delegated),
                send_on(delegated),
            ],
        ),
        (ROLE_CLIENT, "CLI", &[send_on(request), recv_on(reply)]),
        (ROLE_SENDERS[0], "S5", &[send_on(storm)]),
        (ROLE_SENDERS[1], "S6", &[send_on(storm)]),
        (ROLE_SENDERS[2], "S7", &[send_on(storm)]),
        (ROLE_SINK, "SNK", &[recv_on(storm)]),
    ];

    let mut granted = 0;
    for (id, name, grants) in roles {
        let space = match build_space(tables, id) {
            Ok(space) => space,
            Err(e) => {
                let _ = writeln!(console, "ipc SELF-TEST FAILED: {e}");
                return false;
            }
        };
        let Some(mut caps) = crate::cap::empty_caps() else {
            let _ = writeln!(console, "ipc SELF-TEST FAILED: no heap for a capability table");
            return false;
        };
        for cap in grants {
            if crate::cap::install(&mut caps, *cap).is_none() {
                let _ = writeln!(console, "ipc SELF-TEST FAILED: could not grant task {id}");
                return false;
            }
            granted += 1;
        }
        if !sched::spawn_user(name, user_task, space, caps) {
            let _ = writeln!(console, "ipc SELF-TEST FAILED: could not spawn task {id}");
            return false;
        }
    }

    let (objects, live) = obj::census();
    let _ = writeln!(
        console,
        "ipc: {} endpoints, {objects} object(s) ({live} live), {granted} capabilities granted \
         to 6 tasks",
        ipc::NUM_ENDPOINTS,
    );

    let faults_before = user_faults();
    // SAFETY: as `selftest` — the timer is calibrated and its vector is the only
    // unmasked source.
    let Ok(_hz) = (unsafe { crate::irq::start_ticking() }) else {
        let _ = writeln!(console, "ipc SELF-TEST FAILED: the timer would not start");
        return false;
    };

    sched::start();

    // SAFETY: nothing after this expects to be interrupted.
    unsafe { crate::irq::stop_ticking() };

    let ipc = ipc::stats();
    let (blocks, wakeups, died_blocked) = sched::block_counts();
    let faults = user_faults() - faults_before;
    let still_blocked = sched::blocked_tasks();
    let after = mem::frames_in_use();

    let _ = writeln!(
        console,
        "ipc: {} messages sent and {} received ({} handed straight to a waiting receiver, \
         {} buffered), {} capability transferred",
        ipc.sent, ipc.received, ipc.delivered, ipc.buffered, ipc.caps_moved,
    );
    let _ = writeln!(
        console,
        "ipc: {} send(s) waited for a ring slot ({} on the request endpoint, {} on the storm), \
         {} receive(s) waited for a message; {blocks} parks, {wakeups} wake-ups",
        ipc.send_blocks,
        ipc::send_blocks_on(ipc::REQUEST_EP),
        ipc::send_blocks_on(ipc::STORM_EP),
        ipc.recv_blocks,
    );

    if faults != 0 {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {faults} ring-3 fault(s) during a phase where nothing \
             should have died"
        );
        return false;
    }
    if ipc.sent != EXPECTED_MESSAGES || ipc.received != EXPECTED_MESSAGES {
        // Not "at least", and both halves: a protocol that delivered a message
        // twice, or that let a revoked handle through, or that left one in a ring
        // nobody drained, lands here rather than reading as success.
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {} sent and {} received, expected exactly \
             {EXPECTED_MESSAGES} of each",
            ipc.sent, ipc.received,
        );
        return false;
    }
    let request_blocks = ipc::send_blocks_on(ipc::REQUEST_EP);
    let storm_blocks = ipc::send_blocks_on(ipc::STORM_EP);
    if request_blocks < MIN_REQUEST_BLOCKS || storm_blocks < MIN_STORM_BLOCKS {
        // A ring big enough never to fill makes every other assertion here pass
        // while the blocking-send path has never run.
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {request_blocks} blocked send(s) on the request endpoint \
             (needs {MIN_REQUEST_BLOCKS}) and {storm_blocks} on the storm endpoint \
             (needs {MIN_STORM_BLOCKS})"
        );
        return false;
    }
    if blocks != wakeups {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {blocks} task(s) parked but {wakeups} were woken"
        );
        return false;
    }
    if still_blocked != 0 || died_blocked != 0 {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {still_blocked} task(s) still blocked, {died_blocked} died \
             while parked"
        );
        sched::describe(console);
        return false;
    }
    if ipc.caps_moved != 1 {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {} capabilities crossed an endpoint, expected 1",
            ipc.caps_moved,
        );
        return false;
    }

    // The revocation, checked from the kernel's side as well as the program's.
    // The client reported that its handle stopped working; this says the *object*
    // is what stopped existing, which is the claim that "revoked" makes.
    let revocations = REVOCATIONS.load(Ordering::Relaxed);
    if revocations != 1 || obj::get(delegated).is_some() {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: {revocations} revocation(s), and the delegated object is \
             {}",
            if obj::get(delegated).is_some() { "still live" } else { "gone" },
        );
        return false;
    }
    // A revoked slot is reusable, and reusing it must not resurrect the old
    // reference: the generation moved on, so the same `ObjectRef` naming a
    // freshly created object still fails to resolve.
    let Some(reused) = obj::create(Object::Endpoint { id: ipc::DELEGATED_EP }) else {
        let _ = writeln!(console, "ipc SELF-TEST FAILED: the revoked slot was not reusable");
        return false;
    };
    if reused.index != delegated.index || reused.generation == delegated.generation {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: the revoked slot came back as index {} generation {} \
             (was {} / {})",
            reused.index, reused.generation, delegated.index, delegated.generation,
        );
        return false;
    }
    if obj::get(delegated).is_some() {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: the stale reference resolves against the slot's new tenant"
        );
        return false;
    }
    obj::revoke(reused);

    let _ = writeln!(
        console,
        "ipc: the delegated object is gone; its slot came back at generation {} and the old \
         reference still resolves to nothing",
        reused.generation,
    );

    if after != before {
        let _ = writeln!(
            console,
            "ipc SELF-TEST FAILED: six address spaces did not come back \
             ({before} -> {after} frames still out)"
        );
        return false;
    }
    let _ = writeln!(
        console,
        "ipc: 6 tasks finished, every task's frames returned ({before} -> {after} frames out)"
    );
    true
}

/// Run the same program twice, in two address spaces, and make one of them fault.
///
/// The criterion for phase 3.2, and it is several claims the one run establishes:
///
/// - **a real ELF was loaded** — parsed, not assembled here: its entry point,
///   segment count and per-segment rights were read out of the image.
/// - **the two spaces are two spaces** — the same virtual address resolves to
///   different physical frames in each, and the same program prints a different
///   id because the page under [`USER_DATA_VA`] differs.
/// - **the writable segment is writable and private** — the program stamps its id
///   into a string in `.data` before printing it, so a read-only or shared second
///   segment would show up as a fault or as the wrong digit.
/// - **`.bss` arrived zeroed** — `p_memsz` exceeds `p_filesz`, and the program
///   checks the tail itself.
/// - **a fault kills one task** — task 2 dereferences null, dies, and task 1 goes
///   on to print a line that could not exist if it had not.
/// - **the dead task's tree came back** — every frame it owned, tables included.
///
/// # Safety
/// Called once, after [`init`], with the timer calibrated.
pub unsafe fn selftest(console: &mut Console, tables: &Tables) -> bool {
    let image = match Elf::parse(USER_IMAGE) {
        Ok(image) => image,
        Err(e) => {
            let _ = writeln!(console, "user SELF-TEST FAILED: {}", e.as_str());
            return false;
        }
    };
    let segments = image.segments().count();
    let _ = writeln!(
        console,
        "user: image {} bytes, entry {:#x}, {segments} loadable segment(s)",
        USER_IMAGE.len(),
        image.entry(),
    );

    let before = mem::frames_in_use();
    let mut roots = [0u64; 2];
    let mut bases = [0u64; 2];
    for (index, id) in [1u8, 2].into_iter().enumerate() {
        let space = match build_space(tables, id) {
            Ok(space) => space,
            Err(e) => {
                let _ = writeln!(console, "user SELF-TEST FAILED: {e}");
                return false;
            }
        };
        roots[index] = space.root();
        bases[index] = space.translate(USER_BASE).unwrap_or(0);
        // SAFETY: a tree this kernel just built, reachable through the linear map.
        let leaks = unsafe { crate::addrspace::user_reachable_kernel_slots(space.root()) };
        if leaks != 0 {
            // Invisible if wrong: a `PTE_USER` bit on a kernel PML4 entry faults
            // nowhere, changes no kernel behaviour, appears in no log, and makes
            // the whole kernel readable from ring 3.
            let _ = writeln!(
                console,
                "user SELF-TEST FAILED: {leaks} kernel PML4 slot(s) are reachable from ring 3"
            );
            return false;
        }
        let name = if id == 1 { "U1" } else { "U2" };
        // Phase 3.2's two programs are granted nothing at all, and that is the
        // statement: every syscall they make is one that needs no authority. The
        // capability-carrying tasks arrive in [`selftest_ipc`].
        let Some(caps) = crate::cap::empty_caps() else {
            let _ = writeln!(console, "user SELF-TEST FAILED: no heap for a capability table");
            return false;
        };
        if !sched::spawn_user(name, user_task, space, caps) {
            let _ = writeln!(console, "user SELF-TEST FAILED: could not spawn task {id}");
            return false;
        }
    }

    let _ = writeln!(
        console,
        "user: two spaces, cr3 {:#x} and {:#x}; {USER_BASE:#x} -> {:#x} and {:#x}",
        roots[0], roots[1], bases[0], bases[1],
    );
    if bases[0] == bases[1] || bases[0] == 0 || bases[1] == 0 {
        // The single sentence this phase is about. One virtual address resolving
        // to one frame in both trees is not isolation, it is a shared mapping
        // wearing two `CR3` values.
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: {USER_BASE:#x} resolves to the same frame in both spaces"
        );
        return false;
    }

    let faults_before = user_faults();
    let ticks_before = crate::irq::ticks_from_ring3();
    // SAFETY: the timer is calibrated and its vector is the only unmasked source.
    let Ok(hz) = (unsafe { crate::irq::start_ticking() }) else {
        let _ = writeln!(console, "user SELF-TEST FAILED: the timer would not start");
        return false;
    };

    sched::start();

    // SAFETY: nothing after this expects to be interrupted.
    unsafe { crate::irq::stop_ticking() };

    let from_ring3 = crate::irq::ticks_from_ring3() - ticks_before;
    let faults = user_faults() - faults_before;
    let syscalls = SYSCALLS.load(Ordering::Relaxed);
    let refused = REFUSED.load(Ordering::Relaxed);
    let written = BYTES_WRITTEN.load(Ordering::Relaxed);
    let (_, _, switches) = sched::switch_counts();
    let yields = YIELD_CALLS.load(Ordering::Relaxed);
    let (spaces, frames) = sched::reaped_spaces();
    let after = mem::frames_in_use();

    let _ = writeln!(
        console,
        "user: {syscalls} syscalls served ({refused} refused), {written} bytes written, \
         {yields} Yield call(s) causing {switches} switch(es)"
    );
    let _ = writeln!(
        console,
        "user: {from_ring3} timer interrupts arrived from ring 3 at {hz} Hz \
         (they used TSS.rsp0, nothing else could have)"
    );
    let _ = writeln!(
        console,
        "user: {spaces} address space(s) torn down, {frames} frames returned; \
         {before} -> {after} frames still out"
    );

    let mut ok = true;
    if written == 0 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: ring 3 wrote nothing - it never ran, or the ELF did not load"
        );
        ok = false;
    }
    if faults != 1 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: {faults} ring-3 fault(s), expected exactly one"
        );
        ok = false;
    }
    if from_ring3 == 0 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: no interrupt arrived while ring 3 was executing"
        );
        ok = false;
    }
    if yields == 0 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: no `Yield` reached the kernel from ring 3"
        );
        ok = false;
    }
    if refused != 0 {
        let _ = writeln!(console, "user SELF-TEST FAILED: {refused} syscall(s) were not understood");
        ok = false;
    }
    if spaces != 2 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: {spaces} of 2 address spaces were torn down - \
             a dead task's page tables are leaking until reboot"
        );
        ok = false;
    }
    // The equation, not the claim. Both spaces were built and both were destroyed,
    // so the pool must be exactly where it started; a shortfall is frames the
    // teardown walk did not reach, and a surplus is frames it freed twice.
    if after != before {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: {} frame(s) {} - a dead task's page tables are \
             leaking, or something was freed twice",
            before.abs_diff(after),
            if after > before { "were never returned" } else { "came back twice" },
        );
        ok = false;
    }
    ok
}

/// Force one non-canonical return address and check where the fault lands.
///
/// The hazard `docs/ROADMAP.md` names for 3.1, and it is a privilege escalation
/// rather than a crash. `sysretq` takes `RIP` from `RCX` and, on **Intel**, raises
/// `#GP` if it is non-canonical — before the drop to ring 3, so the fault is
/// delivered in ring 0, on the kernel stack, at an address ring 3 chose.
///
/// So the arch crate checks canonicality on the way out and returns through
/// `iretq` instead, which handles any `RIP` and delivers the `#GP` in ring 3.
///
/// The corruption is the kernel's own doing, deliberately: `syscall` overwrites
/// `RCX` with a return address that is canonical by construction, so a program
/// cannot easily arrange this for itself. The realistic route is a kernel that
/// *modifies* the saved return address — which is exactly what this does, in one
/// place, under a flag.
///
/// # Safety
/// Called once, after [`selftest`], with the timer calibrated.
pub unsafe fn selftest_noncanonical(console: &mut Console, tables: &Tables) -> bool {
    let faults_before = user_faults();
    let before = mem::frames_in_use();
    ARM_NONCANONICAL.store(true, Ordering::SeqCst);

    let space = match build_space(tables, 1) {
        Ok(space) => space,
        Err(e) => {
            let _ = writeln!(console, "sysret SELF-TEST FAILED: {e}");
            return false;
        }
    };
    let Some(caps) = crate::cap::empty_caps() else {
        let _ = writeln!(console, "sysret SELF-TEST FAILED: no heap for a capability table");
        return false;
    };
    if !sched::spawn_user("N", user_task, space, caps) {
        let _ = writeln!(console, "sysret SELF-TEST FAILED: could not spawn the task");
        return false;
    }
    let _ = writeln!(
        console,
        "sysret: forcing a non-canonical return address ({NONCANONICAL_RIP:#x}) \
         on the program's first syscall"
    );

    // SAFETY: as `selftest`.
    let _ = unsafe { crate::irq::start_ticking() };
    sched::start();
    // SAFETY: nothing after this expects to be interrupted.
    unsafe { crate::irq::stop_ticking() };

    ARM_NONCANONICAL.store(false, Ordering::SeqCst);
    let faults = user_faults() - faults_before;
    let irets = arch_syscall::iret_returns();
    let after = mem::frames_in_use();

    if faults == 0 {
        let _ = writeln!(
            console,
            "sysret SELF-TEST FAILED: the corrupted return address caused no fault at all"
        );
        return false;
    }
    // The assertion that makes the mitigation falsifiable, which the fault above
    // does not. On this emulator — and on any AMD part — `sysretq` does not check
    // the address: it loads it and the fetch faults in ring 3, which is what the
    // check produces anyway. The two are distinguishable only on Intel silicon,
    // where the unchecked path faults in *ring 0*. So the boot asserts on the
    // decision rather than its consequence: one return went out the slow way, and
    // that is false the moment the check is removed.
    if irets == 0 {
        let _ = writeln!(
            console,
            "sysret SELF-TEST FAILED: the return took `sysretq` with a non-canonical address - \
             on Intel that #GP is delivered in ring 0"
        );
        return false;
    }
    if after != before {
        let _ = writeln!(
            console,
            "sysret SELF-TEST FAILED: the killed task's space did not come back \
             ({before} -> {after} frames still out)"
        );
        return false;
    }
    let _ = writeln!(
        console,
        "sysret: {irets} return(s) went out through iretq instead; the fault arrived in ring 3, \
         killed only that task, and its {} frames came back",
        sched::reaped_spaces().1,
    );
    true
}
