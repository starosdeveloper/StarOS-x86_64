//! Round-robin scheduling for kernel threads.
//!
//! The policy half of phase 2.4; the mechanism is
//! [`staros_arch_x86_64::context`]. A task is a kernel thread with its own stack
//! and its own saved callee-saved registers, and it leaves the CPU exactly two
//! ways: the timer interrupt asks for a reschedule and the IRQ epilogue honours
//! it, or the task's entry function returns and [`exit`] switches away for good.
//!
//! There is deliberately no `yield_now`. A voluntary yield is a scheduler
//! primitive with nothing to call it until a syscall does, in phase 3.1, and the
//! self-test below must not use one: two tasks that cooperate would interleave
//! whether or not preemption works, which is precisely the criterion this phase
//! has to be able to fail. The voluntary switch path is exercised regardless —
//! [`exit`] is one, taken twice.
//!
//! ## What this is not, yet
//! The aarch64 tree's `sched` is the same shape carrying more phases of cargo:
//! an on-cpu flag, per-core arrays, a lost-wakeup flag, sleep deadlines. None of
//! that is here, and none of it is stubbed, because every one of those fields
//! exists to solve a problem this kernel does not have yet:
//!
//! - **No `on_cpu`, no per-core arrays.** Both exist to keep one core from
//!   loading a context another core has not finished saving. With one core the
//!   switch that saves a context and the pick that could load it are the same
//!   instruction stream, so the window does not exist. Phase 4 opens it, and that
//!   is where the flag belongs — added with a failure that motivates it, not
//!   inherited as decoration.
//! - **No `wake_pending`.** The aarch64 tree needs it because a peer on another
//!   core can wake a task in the window between it registering as a waiter and it
//!   actually parking. Here the only thing that ever wakes a task is *another
//!   task's* send or receive, and another task cannot execute until this one has
//!   switched away — the window is not narrow, it is empty. Phase 4 creates it,
//!   and this is the sentence to delete then.
//! - **No sleep deadlines.** `SleepUntil` and `WaitAny` are notification-shaped
//!   syscalls that arrive with device drivers in user space, and a `Sleeping`
//!   state nothing enters would make [`Scheduler::pick_next`] look like it
//!   handled a case it has never seen.
//!
//! What phase 3.3 *did* add is the pair that IPC cannot be built without: the
//! [`State::Blocked`] state and the [`Task::mailbox`] a sender delivers into,
//! plus a [capability table](crate::cap) per task. All three were deliberately
//! absent in 2.4 and 3.2 — a task that could be blocked with nothing to block on
//! is a state machine with an unreachable state — and all three now have exactly
//! one caller each in [`crate::ipc`].
//!
//! What *is* here is what a single core genuinely needs, including the part that
//! is easy to skip: [`PREV`] and [`post_switch`]. A task cannot free its own
//! stack, because it is standing on it. So an exiting task hands its slot to
//! whichever context this core resumes next, and that context — already on a
//! different stack — does the freeing. Without it a kernel thread's 32 KiB is
//! lost until reboot, silently, and the only way to notice is to count.
//!
//! ## Locking discipline
//! The scheduler lives in one [`SpinLock`], and the guard is **never** held
//! across a [`context_switch`]. Holding it would leave the lock owned by a task
//! that is no longer running, and the next thing to want it — including this same
//! core, one tick later — would spin forever. So every operation takes the lock,
//! extracts raw [`CpuContext`] pointers, drops the guard, and only then switches.
//!
//! Interrupt masking is a separate concern and outlives the lock: it has to span
//! the *whole* switch, or the timer could preempt this core between choosing a
//! task and entering it. Callers mask around the entire operation; the lock's own
//! masking nests harmlessly inside.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use staros_arch_x86_64::context::{self, context_switch, CpuContext};
use staros_arch_x86_64::{cpu, gdt, syscall};

use crate::addrspace::AddressSpace;
use crate::cap::{self, Cap, CapTable};
use crate::console::Console;
use crate::ipc::KMessage;
use crate::kprintln;
use crate::sync::SpinLock;

/// Per-task kernel stack size in 64-bit words (32 KiB), as on aarch64.
const STACK_WORDS: usize = 4096;

/// "No task": the value [`Scheduler::current`] and [`PREV`] hold when this core
/// is in its bootstrap context rather than in a task.
const NONE: usize = usize::MAX;

/// Lifecycle state of a task slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Runnable but not currently on the CPU.
    Ready,
    /// Currently executing.
    Running,
    /// Parked on an IPC wait queue: not runnable until a peer delivers a message
    /// or frees a ring slot. The scheduler cannot say *what* a task is waiting
    /// for — the queues live in [`crate::ipc`], which is what
    /// [`crate::ipc::waiting_on`] is for.
    Blocked,
    /// Finished; will not be scheduled again.
    Dead,
}

impl State {
    /// What the boot log calls this state.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Dead => "dead",
        }
    }
}

/// A schedulable kernel thread.
struct Task {
    /// Saved callee-saved registers and stack pointer.
    ctx: CpuContext,
    /// This task's kernel stack, on the heap rather than inline in the slot.
    ///
    /// Not merely to keep [`Task`] small: a task's stack must not move for as
    /// long as the task exists, and an inline array moves whenever the `Vec`
    /// holding it grows. A separate allocation is pinned by construction.
    stack: Box<[u64]>,
    /// Top of that stack, recorded once at spawn.
    ///
    /// Not derived on demand from `stack`, because the reaper replaces a dead
    /// task's stack with an empty box and the derived answer would then be the
    /// address of nothing. It is only ever *used* for a live task, but a field
    /// that is wrong for a dead one is a field waiting to be read by mistake.
    kernel_stack_top: u64,
    /// The tree this task runs in, as a `CR3` value.
    ///
    /// A kernel thread carries the kernel's own root; a ring-3 task carries its
    /// private one. Phase 2.4 deliberately left this field out, on the grounds
    /// that a field holding the same value for everyone is a comment. Phase 3.2
    /// is where it stops being one.
    cr3: u64,
    /// The ring-3 address space, if this is a user task. `None` for a kernel
    /// thread, which runs in the kernel's own tree and owns no user pages.
    space: Option<AddressSpace>,
    /// What this task is permitted to do. A kernel thread's table is empty and
    /// stays empty; a ring-3 task's is seeded at spawn and grows when a
    /// capability is delegated to it over IPC.
    caps: CapTable,
    /// A message delivered to this task while it was blocked in `Recv`.
    ///
    /// Filled by [`deliver`] from *inside the sender's* syscall, and taken by the
    /// receiver the moment it is scheduled again. Not a queue: a task can only be
    /// blocked in one receive at a time, so at most one message can be in flight
    /// to it — anything further is buffered at the endpoint, where it belongs.
    mailbox: Option<KMessage>,
    state: State,
    id: usize,
    /// What the boot log calls it. A task is otherwise identified only by a slot
    /// index, and "task 1 finished" is a worse line than "task B finished".
    name: &'static str,
}

/// The kernel's own `CR3`, recorded the first time [`start`] runs.
///
/// Where a core goes when it has no task: the bootstrap context must not be left
/// executing in a tree that is about to be torn down.
///
/// Zero is a *legitimate value* here, and finding that out cost an afternoon.
/// Physical frame 0 is ordinary RAM on a PC, the frame pool hands it out like any
/// other, and on this machine it is what `vm::init` got for the kernel's PML4 —
/// so `CR3` is genuinely 0 and the machine runs perfectly. Any code that reads a
/// zero root as "no root" is therefore wrong, which is why [`enter`] takes an
/// `Option` and not a sentinel.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

/// Make a task's kernel stack and address space current.
///
/// `top` is `None` when there is no task — the bootstrap context, which never
/// takes a ring transition and so has no use for a privilege stack. Leaving the
/// previous value in place is deliberate: the alternative is writing a null into
/// `TSS.rsp0`, and a null there is only ever read by a transition that cannot
/// happen from ring 0.
///
/// Called on **every** switch into a task, and none of the three writes is
/// interchangeable with another:
///
/// - `TSS.rsp0` is what the **CPU** loads when an interrupt arrives while ring 3
///   is executing. It reads the TSS before one kernel instruction runs, so
///   nothing in software can supply it late.
/// - [`syscall::set_kernel_stack`] is what the `syscall` entry stub reads through
///   `GS`, because `syscall` does not switch stacks at all.
/// - `CR3` is the address space. Written only when it changes, because writing it
///   flushes every non-global TLB entry and most switches are between tasks in
///   the same tree.
///
/// Both parameters are `Option` rather than sentinel values, because neither zero
/// nor any other number is available as "leave this alone": physical frame 0 is a
/// real frame that this pool really hands out, and on this machine the kernel's
/// own PML4 lives there.
///
/// Switching `CR3` here — in kernel code, mid-function — is safe for exactly one
/// reason: every tree's upper half is the *same* set of tables (see
/// [`AddressSpace`]), so the instruction after the write, the stack under it and
/// the console it may print to are mapped identically on both sides.
fn enter(top: Option<u64>, cr3: Option<u64>) {
    if let Some(top) = top {
        gdt::set_privilege_stack(top);
        syscall::set_kernel_stack(top);
    }
    let Some(cr3) = cr3 else { return };
    if cpu::read_cr3() != cr3 {
        // SAFETY: `cr3` is a root this kernel built — either `vm::init`'s or an
        // `AddressSpace`'s — and every one of them carries the kernel's upper
        // half verbatim, so the code executing this remains mapped across it.
        unsafe { cpu::write_cr3(cr3) };
    }
}

/// Allocate a zeroed kernel stack, or `None` if the heap is exhausted.
///
/// Fallible rather than panicking because spawning is something a caller is
/// allowed to fail at — and because a zeroed stack is what makes a mistake in
/// [`staros_arch_x86_64::context::plant`] present as a jump to address zero,
/// which since phase 1.4 is a named page fault rather than a wild branch.
fn alloc_stack() -> Option<Box<[u64]>> {
    let mut stack: Vec<u64> = Vec::new();
    stack.try_reserve_exact(STACK_WORDS).ok()?;
    // Neither of these can reallocate: the capacity is already exact.
    stack.resize(STACK_WORDS, 0);
    Some(stack.into_boxed_slice())
}

/// Move `task` to the heap, or `None` if the heap is exhausted.
///
/// `Box::new` aborts on allocation failure and `Box::try_new` is still unstable,
/// so this goes the long way round through the fallible API that does exist: a
/// `Vec` with exactly one element's worth of capacity cannot reallocate on `push`
/// or on `into_boxed_slice`, and a one-element `Box<[Task]>` has the same layout
/// as a `Box<Task>`.
fn try_box(task: Task) -> Option<Box<Task>> {
    let mut v: Vec<Task> = Vec::new();
    v.try_reserve_exact(1).ok()?;
    v.push(task);
    let boxed: Box<[Task]> = v.into_boxed_slice();
    let ptr = Box::into_raw(boxed).cast::<Task>();
    // SAFETY: `ptr` came from `Box::into_raw` on a one-element slice, so it is a
    // valid, uniquely-owned, correctly-aligned `Task` allocated by the global
    // allocator with `Layout::array::<Task>(1)` — which is `Layout::new::<Task>()`.
    // Re-boxing it as a single element frees it with the layout it was allocated
    // with.
    Some(unsafe { Box::from_raw(ptr) })
}

/// The scheduler state.
struct Scheduler {
    /// Every task, live or dead.
    ///
    /// `Vec<Box<Task>>` rather than `Vec<Task>`, and the indirection is load
    /// bearing. A suspended task's saved `RSP` points into its own stack and the
    /// switch writes through a raw pointer into its slot; if a later spawn grew a
    /// `Vec<Task>`, every existing task would be memcpy'd to a new address and
    /// those pointers would be left dangling. Boxing each task means growth moves
    /// the pointers, never the tasks.
    ///
    /// `clippy::vec_box` reads this as redundant indirection, which is the right
    /// call whenever a `Vec`'s elements are only ever reached *through the `Vec`*.
    /// These are not.
    #[allow(clippy::vec_box)]
    tasks: Vec<Box<Task>>,
    /// The context `start` was called from on each core, returned to when nothing
    /// is runnable there.
    ///
    /// One per core, not one for the machine. A second core entering the scheduler
    /// would otherwise overwrite the first core's saved context, and the first
    /// core would return from its next idle into the second core's stack — the
    /// kind of failure that only happens once the machine is doing real work.
    bootstrap: [CpuContext; MAX_CPUS],
    /// The slot each core is running, or [`NONE`] where that core is in its
    /// bootstrap context.
    current: [usize; MAX_CPUS],
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            bootstrap: [const { CpuContext::empty() }; MAX_CPUS],
            current: [NONE; MAX_CPUS],
        }
    }

    /// First runnable slot, if any.
    fn first_ready(&self) -> Option<usize> {
        (0..self.tasks.len()).find(|&i| self.tasks[i].state == State::Ready)
    }

    /// Next runnable slot after `from`, scanning round-robin. Never returns
    /// `from` itself, which is what makes a switch a switch.
    fn pick_next(&self, from: usize) -> Option<usize> {
        let n = self.tasks.len();
        if n == 0 {
            return None;
        }
        (1..=n)
            .map(|off| (from + off) % n)
            .find(|&i| self.tasks[i].state == State::Ready)
    }
}

static SCHED: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

/// Set by the timer tick to request a reschedule at the next IRQ epilogue, per
/// core.
///
/// One flag for the machine would mean a tick on any core rescheduling *some*
/// core — whichever reached its epilogue first — while the one that actually took
/// the interrupt kept running. The counters would still look right, which is what
/// makes it worth spelling out.
static NEED_RESCHED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// How many cores the scheduler tracks. The arch crate's `PerCpu` table is the
/// same size, and the index used here is the one it hands out.
const MAX_CPUS: usize = staros_arch_x86_64::syscall::MAX_CPUS;

/// Which core is executing, as an index.
fn me() -> usize {
    core::cmp::min(staros_arch_x86_64::syscall::cpu_index() as usize, MAX_CPUS - 1)
}

/// The slot this core last switched *away from*, handed to whichever context it
/// resumes next so that context can — if the task exited — free its kernel stack.
/// [`NONE`] means the switch came *from* the bootstrap context and there is
/// nothing to settle.
///
/// Written by every switch-out and read and cleared solely by whatever this core
/// resumes into — so it is per core, and sharing one across cores would hand a
/// task's kernel stack to a context on another core that never ran it.
static PREV: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(NONE) }; MAX_CPUS];

/// Context switches performed.
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Switches that happened because the timer asked, rather than because a task
/// yielded. Zero here with tasks that never yield means preemption is not
/// happening, whatever else the log says.
static PREEMPTIONS: AtomicU64 = AtomicU64::new(0);

/// Switches a task asked for itself, through [`yield_now`]. The other half of the
/// same distinction: a scheduler that only ever preempts and a scheduler that only
/// ever cooperates both look like "switches happened" from the outside.
static YIELDS: AtomicU64 = AtomicU64::new(0);

/// Tasks parked on an IPC wait queue, and tasks woken off one.
///
/// Two numbers rather than one, because they answer different questions. Parks
/// with no wakeups is a system that blocked and stayed blocked; equal counts at
/// the end of a run mean everything that went to sleep was woken by somebody.
static BLOCKS: AtomicU64 = AtomicU64::new(0);
static WAKEUPS: AtomicU64 = AtomicU64::new(0);

/// Tasks that died while standing in a wait queue.
///
/// Nonzero is not an error — a ring-3 fault kills a task wherever it is — but it
/// is the count that says [`exit`]'s call to [`crate::ipc::forget_task`] had work
/// to do. Without that call the queue keeps the slot of a task whose stack has
/// been reaped, and the next send delivers a message into it.
static DIED_BLOCKED: AtomicU64 = AtomicU64::new(0);

/// Dead-task stacks reclaimed, and the 64-bit words that returned to the heap.
static REAPED_STACKS: AtomicU64 = AtomicU64::new(0);
static REAPED_WORDS: AtomicU64 = AtomicU64::new(0);

/// Ring-3 address spaces torn down, and the frames — data pages and page tables
/// both — that went back to the pool.
///
/// The same accounting as the stacks, for the same reason. A task that faults and
/// dies costs the machine its whole tree; leaving it mapped changes nothing
/// anybody would notice until the pool runs out, which on a machine with
/// gigabytes is never during a boot and always during a run.
static REAPED_SPACES: AtomicU64 = AtomicU64::new(0);
static REAPED_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Switches performed, how many were preemptions, and how many were voluntary.
#[must_use]
pub fn switch_counts() -> (u64, u64, u64) {
    (
        SWITCHES.load(Ordering::Relaxed),
        PREEMPTIONS.load(Ordering::Relaxed),
        YIELDS.load(Ordering::Relaxed),
    )
}

/// Ring-3 address spaces torn down so far, and the frames that returned.
#[must_use]
pub fn reaped_spaces() -> (u64, u64) {
    (
        REAPED_SPACES.load(Ordering::Relaxed),
        REAPED_FRAMES.load(Ordering::Relaxed),
    )
}

/// The address space of the running task, if it has one.
#[must_use]
pub fn current_space() -> Option<AddressSpace> {
    let cpu = me();
    let sched = SCHED.lock();
    if sched.current[cpu] == NONE {
        return None;
    }
    sched.tasks[sched.current[cpu]].space
}

/// Dead-task kernel stacks reaped so far, and the bytes that freed.
#[must_use]
pub fn reaped_stacks() -> (u64, u64) {
    (
        REAPED_STACKS.load(Ordering::Relaxed),
        REAPED_WORDS.load(Ordering::Relaxed) * 8,
    )
}

/// How many task slots are still parked on a wait queue.
///
/// Zero at the end of a run is the difference between "every task finished" and
/// "every task that could finish did". A blocked task at shutdown is a deadlock
/// or a lost message, and it produces no other symptom — the boot simply moves
/// on, because a scheduler with nothing runnable is indistinguishable from a
/// scheduler with nothing left to do.
#[must_use]
pub fn blocked_tasks() -> usize {
    let sched = SCHED.lock();
    sched
        .tasks
        .iter()
        .filter(|t| t.state == State::Blocked)
        .count()
}

/// How many task slots exist. A high-water mark: slots are never reused, because
/// their indices name tasks and reuse would need proof the dead one has left.
#[must_use]
pub fn task_count() -> usize {
    SCHED.lock().tasks.len()
}

/// Print one line per task slot: what it was called, how it ended, and whether
/// its stack is still held.
///
/// Each slot is snapshotted under a *separate*, short hold of the scheduler lock,
/// and printed after that hold is released. Printing under the scheduler lock
/// would nest the console lock inside it, which is an ordering nothing else in
/// this kernel uses and therefore the kind of thing that becomes a deadlock the
/// first time some future code takes them the other way round.
pub fn describe(console: &mut Console) {
    use core::fmt::Write;

    for i in 0..task_count() {
        let snapshot = {
            let sched = SCHED.lock();
            sched
                .tasks
                .get(i)
                .map(|t| (t.id, t.name, t.state, t.stack.len() * 8))
        };
        let Some((id, name, state, stack_bytes)) = snapshot else {
            continue;
        };
        // What a blocked task is waiting for lives in the endpoint tables, not
        // here: "blocked" alone cannot tell a client owed a reply from one parked
        // on a queue nothing will ever send to.
        let waiting = if state == State::Blocked {
            crate::ipc::waiting_on(i)
        } else {
            None
        };
        let held = if stack_bytes == 0 { "(reclaimed)" } else { "held" };
        let kib = stack_bytes / 1024;
        let _ = match waiting {
            Some((ep, true)) => writeln!(
                console,
                "sched: task {id} \"{name}\" blocked sending on ep{ep}, {kib} KiB of stack {held}",
            ),
            Some((ep, false)) => writeln!(
                console,
                "sched: task {id} \"{name}\" blocked receiving on ep{ep}, {kib} KiB of stack {held}",
            ),
            None => writeln!(
                console,
                "sched: task {id} \"{name}\" {}, {kib} KiB of stack {held}",
                state.as_str(),
            ),
        };
    }
}

/// Create a kernel thread that will run `entry`, and make it runnable.
///
/// Returns `false` if the heap could not supply a stack or a slot — the machine's
/// answer, not a number chosen in advance.
pub fn spawn(name: &'static str, entry: extern "C" fn()) -> bool {
    cap::empty_caps().is_some_and(|caps| spawn_with(name, entry, None, caps))
}

/// Create a **ring-3** task: a kernel thread whose entry drops into `space`,
/// holding exactly the capabilities in `caps`.
///
/// The task owns the space: when it dies, its successor tears the tree down and
/// returns every frame (see [`post_switch`]).
///
/// Capabilities are handed over at creation rather than granted afterwards
/// because there is no moment in between: a task becomes runnable the instant it
/// is in the table, and a ring-3 program that ran one instruction with an empty
/// capability table would see every syscall refused for reasons that have nothing
/// to do with what it was granted.
pub fn spawn_user(
    name: &'static str,
    entry: extern "C" fn(),
    space: AddressSpace,
    caps: CapTable,
) -> bool {
    spawn_with(name, entry, Some(space), caps)
}

/// The body of both, with the address space and the grants as the difference.
fn spawn_with(
    name: &'static str,
    entry: extern "C" fn(),
    space: Option<AddressSpace>,
    caps: CapTable,
) -> bool {
    // Point the arch crate's trampoline back at this module. Done here, in the
    // only way a task can come into existence, rather than in an `init` a future
    // caller could forget: the trampoline is unreachable until a task exists, and
    // a task cannot exist without passing through this line. Re-registering the
    // same two pointers on every spawn is free.
    context::set_hooks(post_switch, exit);

    // Build the whole task *before* taking the lock. Partly to keep the lock
    // short, but mainly to keep the lock order a straight line: allocating takes
    // the heap's lock, and doing that underneath the scheduler's would nest two
    // locks for no reason.
    let Some(mut stack) = alloc_stack() else {
        return false;
    };
    let mut ctx = CpuContext::empty();
    if !ctx.init(entry, &mut stack) {
        return false;
    }
    // The same rounding `context::plant` does, and for the same reason: a
    // `Box<[u64]>` promises eight-byte alignment, and both `TSS.rsp0` and the
    // syscall stub push structures the ABI wants sixteen-byte aligned.
    let kernel_stack_top = (stack.as_ptr() as u64 + stack.len() as u64 * 8) & !0xf;
    let Some(mut task) = try_box(Task {
        ctx,
        stack,
        kernel_stack_top,
        // A user task runs in its own tree; a kernel thread runs in whatever tree
        // the kernel is in, read now rather than stored once so a spawn before
        // `vm::init` would be visibly wrong instead of quietly inheriting a root
        // that does not exist yet.
        cr3: space.map_or_else(cpu::read_cr3, |s| s.root()),
        space,
        caps,
        mailbox: None,
        state: State::Ready,
        id: 0,
        name,
    }) else {
        return false;
    };

    let mut sched = SCHED.lock();
    if sched.tasks.try_reserve(1).is_err() {
        return false;
    }
    task.id = sched.tasks.len();
    sched.tasks.push(task);
    true
}

/// Begin scheduling. Saves the bootstrap context, runs tasks until none is
/// runnable, and returns here.
///
/// A loop rather than a single switch, because a task that exits with another
/// still ready switches straight into it, but a task that exits with nothing
/// ready comes back *here* — and the next spawn (or, from phase 4, another core's
/// work) may make something ready again. With one core the loop ends the first
/// time it finds nothing, which is exactly when the system is finished.
pub fn start() {
    // SAFETY: enter an interrupt-masked critical section for the switch. Tasks
    // themselves run with interrupts on: the trampoline does `sti`, and a task
    // resumed by a preemption returns through `iretq`, which restores `IF` from
    // the frame it was interrupted with.
    let saved = unsafe { cpu::irq_save() };
    let cpu = me();
    // The tree the kernel is in right now. Recorded here because this is the one
    // place guaranteed to run before any task has switched `CR3` away from it,
    // and the bootstrap context has to be able to get back.
    KERNEL_ROOT.store(cpu::read_cr3(), Ordering::SeqCst);

    loop {
        let picked = {
            let mut sched = SCHED.lock();
            sched.first_ready().map(|first| {
                sched.current[cpu] = first;
                sched.tasks[first].state = State::Running;
                // Switching *from* the bootstrap context, which is not a task —
                // nothing for the successor to settle.
                PREV[cpu].store(NONE, Ordering::Relaxed);
                let top = sched.tasks[first].kernel_stack_top;
                let cr3 = sched.tasks[first].cr3;
                let boot: *mut CpuContext = &mut sched.bootstrap[cpu];
                let next: *const CpuContext = &sched.tasks[first].ctx;
                (boot, next, top, cr3)
            })
        };
        let Some((boot_ptr, next_ptr, top, cr3)) = picked else {
            break;
        };
        enter(Some(top), Some(cr3));
        SWITCHES.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the two pointers name distinct contexts — the bootstrap's and a
        // task's — the guard has been dropped, and interrupts are masked. We
        // resume here when this core runs out of tasks.
        unsafe { context_switch(boot_ptr, next_ptr) };
        // Back in the bootstrap context, and possibly in a tree that is about to
        // be freed: return to the kernel's own before anything else runs.
        enter(None, Some(KERNEL_ROOT.load(Ordering::SeqCst)));
        // Settle (and, if it exited, reap) the task that switched back to us.
        post_switch();
    }

    // SAFETY: restores the interrupt state `kmain` was in.
    unsafe { cpu::irq_restore(saved) };
}

/// Voluntarily give up the CPU to the next runnable task.
///
/// Absent in phase 2.4 because nothing could call it; phase 3.1 gives it its
/// caller, the `Yield` syscall. Which means the first thing to yield in this
/// kernel is a ring-3 program, and the round trip it makes — `syscall`, a switch
/// to another task, a switch back, `sysretq` — is the whole of phase 3.1 in one
/// instruction.
///
/// Interrupts are masked for the switch and restored afterwards, so a syscall
/// handler that yields comes back in the state it left: masked, on its own kernel
/// stack, one `sysretq` from ring 3.
pub fn yield_now() {
    // SAFETY: reschedule inside an interrupt-masked critical section.
    let saved = unsafe { cpu::irq_save() };
    if reschedule() {
        YIELDS.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: matching restore; runs when this task is switched back in.
    unsafe { cpu::irq_restore(saved) };
}

/// Whether this core is inside a task rather than in its bootstrap context.
///
/// Asked by the fault path: a fault from ring 3 kills the task that took it, and
/// "kill the task" is only an answer when there is one.
#[must_use]
pub fn in_task() -> bool {
    let cpu = me();
    SCHED.lock().current[cpu] != NONE
}

/// The name of the running task, or `"bootstrap"` outside one. For fault reports.
#[must_use]
pub fn current_name() -> &'static str {
    let cpu = me();
    let sched = SCHED.lock();
    if sched.current[cpu] == NONE {
        return "bootstrap";
    }
    sched.tasks[sched.current[cpu]].name
}

/// Ask for a reschedule at the next IRQ epilogue. Called from the timer tick.
///
/// A flag rather than a switch, because the tick runs with a trap frame half
/// built and the interrupt not yet acknowledged. Switching there would strand the
/// acknowledgement in a task that is no longer on the CPU.
pub fn request_resched() {
    NEED_RESCHED[me()].store(true, Ordering::Relaxed);
}

/// Run at the end of interrupt handling, after the controller has been
/// acknowledged: if a reschedule was asked for, do it now.
///
/// The switch happens *inside* the interrupt handler, on the interrupted task's
/// own kernel stack, with its trap frame already on it. That is the point — the
/// frame stays where it is, the task's saved `RSP` points at it, and when the
/// task is picked again the switch returns into this function, the handler
/// unwinds, and `iretq` puts the task back exactly where the interrupt found it.
pub fn on_irq_epilogue() {
    if NEED_RESCHED[me()].swap(false, Ordering::Relaxed) && reschedule() {
        PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Move from the current task to the next runnable one, if there is one.
///
/// Returns whether a switch actually happened. Must be called with interrupts
/// masked.
fn reschedule() -> bool {
    let prev_ptr: *mut CpuContext;
    let next_ptr: *const CpuContext;
    let next_top: u64;
    let next_cr3: u64;
    let cpu = me();
    {
        let mut sched = SCHED.lock();
        let prev = sched.current[cpu];
        // Not in a task: this core is in its bootstrap context, so there is
        // nothing to switch away from. Happens on every tick that lands during
        // boot, before `start`.
        if prev == NONE {
            return false;
        }
        let Some(next) = sched.pick_next(prev) else {
            return false;
        };
        if sched.tasks[prev].state == State::Running {
            sched.tasks[prev].state = State::Ready;
        }
        sched.tasks[next].state = State::Running;
        sched.current[cpu] = next;
        // Hand `prev` to our successor. Today it only matters for a dead task's
        // stack; `prev` is alive here, so the successor will find nothing to do.
        PREV[cpu].store(prev, Ordering::Relaxed);
        next_top = sched.tasks[next].kernel_stack_top;
        next_cr3 = sched.tasks[next].cr3;
        prev_ptr = &mut sched.tasks[prev].ctx;
        next_ptr = &sched.tasks[next].ctx;
    }
    enter(Some(next_top), Some(next_cr3));
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `pick_next` never returns `prev`, so the two pointers name distinct
    // contexts; the guard is dropped and interrupts are masked. Execution resumes
    // here when this task is scheduled again.
    unsafe { context_switch(prev_ptr, next_ptr) };
    // Resumed as someone's successor: settle (and maybe reap) our predecessor.
    post_switch();
    true
}

/// Park the current task as [`State::Blocked`] and switch away, resuming here
/// once a peer has made it `Ready` again and the scheduler has picked it.
///
/// The caller must **already** have arranged to be woken — registered itself on
/// an endpoint's wait queue under that endpoint's lock — before calling this.
/// Doing it the other way round is the classic lost wakeup.
///
/// On this kernel it is not merely the classic ordering, it is sufficient. The
/// only thing that ever calls [`unblock`] or [`deliver`] is *another task* inside
/// its own `Send` or `Recv`, and with one core another task cannot execute a
/// single instruction until this one has switched away — which happens below,
/// after the state is already `Blocked`. There is no window to lose a wakeup in.
/// Phase 4 opens one, and that is where a `wake_pending` flag belongs.
///
/// Unlike [`reschedule`], this cannot decline. A task that has registered as a
/// waiter and then keeps running would take the message meant for it and never
/// look; so when nothing else is runnable this goes to the bootstrap context,
/// which decides whether the system is finished. A boot that ends there with
/// blocked tasks is a deadlock, and [`describe`] names who was waiting on what.
fn park_and_switch() {
    // SAFETY: the switch happens inside an interrupt-masked critical section;
    // the matching restore runs when this task is resumed.
    let saved = unsafe { cpu::irq_save() };

    let prev_ptr: *mut CpuContext;
    let next_ptr: *const CpuContext;
    let next_top: Option<u64>;
    let next_cr3: u64;
    let cpu = me();
    {
        let mut sched = SCHED.lock();
        let prev = sched.current[cpu];
        // Blocking from the bootstrap context would be blocking the thing that
        // resumes blocked tasks. Nothing does it: every caller arrives from a
        // syscall, which by definition ran in a task.
        assert!(prev != NONE, "blocked outside a task");
        sched.tasks[prev].state = State::Blocked;
        BLOCKS.fetch_add(1, Ordering::Relaxed);
        PREV[cpu].store(prev, Ordering::Relaxed);
        prev_ptr = &mut sched.tasks[prev].ctx;
        match sched.pick_next(prev) {
            Some(next) => {
                sched.tasks[next].state = State::Running;
                sched.current[cpu] = next;
                next_top = Some(sched.tasks[next].kernel_stack_top);
                next_cr3 = sched.tasks[next].cr3;
                next_ptr = &sched.tasks[next].ctx;
            }
            None => {
                sched.current[cpu] = NONE;
                next_top = None;
                next_cr3 = KERNEL_ROOT.load(Ordering::SeqCst);
                next_ptr = &sched.bootstrap[cpu];
            }
        }
    }
    enter(next_top, Some(next_cr3));
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `pick_next` never returns `prev` and the bootstrap context is not a
    // task, so the two pointers name distinct contexts; the guard is dropped and
    // interrupts are masked. Execution resumes here once a peer unblocks us.
    unsafe { context_switch(prev_ptr, next_ptr) };
    // Resumed as someone's successor: settle (and maybe reap) our predecessor.
    post_switch();

    // SAFETY: matching restore for the save above.
    unsafe { cpu::irq_restore(saved) };
}

/// Block the current task until a peer unblocks it. Called from the `Send` path
/// when the endpoint's ring is full; the receiver that drains a slot wakes us and
/// deposits the message we were carrying.
pub fn block_current() {
    park_and_switch();
}

/// Block the current task until a message is delivered to it, then return that
/// message. Called from the `Recv` path when nothing is buffered.
///
/// The `expect` is not a hopeful assertion: the only path that makes a task
/// `Ready` out of a receive block is [`deliver`], which fills the mailbox *before*
/// it changes the state. A woken receiver with an empty mailbox would mean some
/// other code had unblocked a task standing in a receive queue, which is a kernel
/// bug that must not be papered over by returning an empty message the program
/// would then act on.
#[must_use]
pub fn block_for_message() -> KMessage {
    park_and_switch();
    let cpu = me();
    let mut sched = SCHED.lock();
    let running = sched.current[cpu];
    sched.tasks[running]
        .mailbox
        .take()
        .expect("a receiver was woken without a message")
}

/// Make a blocked task runnable again without switching to it. The caller keeps
/// running; the woken task runs when the scheduler next picks it.
///
/// Waking a task that is not blocked is a no-op rather than an error: a task can
/// die while standing in a wait queue, and [`forget_waiter`] races nothing here
/// only because both run under the same lock.
pub fn unblock(task: usize) {
    let mut sched = SCHED.lock();
    if sched.tasks[task].state == State::Blocked {
        sched.tasks[task].state = State::Ready;
        WAKEUPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Deliver `km` into a blocked receiver's mailbox and make it runnable.
///
/// The mailbox is filled first and the state changed second, which is the
/// ordering [`block_for_message`]'s `expect` depends on.
pub fn deliver(task: usize, km: KMessage) {
    let mut sched = SCHED.lock();
    sched.tasks[task].mailbox = Some(km);
    if sched.tasks[task].state == State::Blocked {
        sched.tasks[task].state = State::Ready;
        WAKEUPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// The slot index of the running task. Used by [`crate::ipc`] to name a waiter.
///
/// Panics outside a task, deliberately: an endpoint queue entry that named the
/// bootstrap context would be a message addressed to something that cannot
/// receive, and every caller reaches here from a syscall.
#[must_use]
pub fn current_id() -> usize {
    let cpu = me();
    let current = SCHED.lock().current[cpu];
    assert!(current != NONE, "IPC outside a task");
    current
}

/// Resolve `handle` against the **running** task's capability table.
///
/// Per-task by construction: there is no way to ask about anyone else's table,
/// which is what makes a handle unforgeable rather than merely opaque.
#[must_use]
pub fn resolve_cap(handle: u32) -> Option<Cap> {
    let cpu = me();
    let sched = SCHED.lock();
    if sched.current[cpu] == NONE {
        return None;
    }
    cap::resolve(&sched.tasks[sched.current[cpu]].caps, handle)
}

/// Install `cap` into the running task's table at its lowest free handle,
/// returning that handle — or `None` if the heap is exhausted.
///
/// This is how a capability that arrived over IPC becomes usable. Growing the
/// table allocates, so this takes the heap's lock underneath the scheduler's.
/// That direction is safe because the heap is a leaf — nothing under it reaches
/// back into the scheduler — and it is the only nesting of the two that happens.
pub fn install_cap_current(cap: Cap) -> Option<u32> {
    let cpu = me();
    let mut sched = SCHED.lock();
    if sched.current[cpu] == NONE {
        return None;
    }
    let current = sched.current[cpu];
    cap::install(&mut sched.tasks[current].caps, cap)
}

/// Tasks parked, tasks woken, and tasks that died while parked.
#[must_use]
pub fn block_counts() -> (u64, u64, u64) {
    (
        BLOCKS.load(Ordering::Relaxed),
        WAKEUPS.load(Ordering::Relaxed),
        DIED_BLOCKED.load(Ordering::Relaxed),
    )
}

/// Terminate the current task and switch away for good. Never returns.
///
/// The task cannot free its own stack — it is standing on it — so it marks itself
/// dead, hands its slot to [`PREV`], and lets whichever context runs next do the
/// freeing from a stack that is not this one.
pub fn exit() -> ! {
    // SAFETY: mask interrupts for the final switch. This task never runs again,
    // so nothing restores the mask on its behalf; the successor's own resume path
    // does that for itself.
    let _ = unsafe { cpu::irq_save() };

    // Leave every wait queue *before* the slot is marked dead. A task can die
    // while parked — a ring-3 fault kills it wherever it stands — and an endpoint
    // that still holds this slot index would hand the next message to a task
    // whose stack has been reclaimed and whose address space no longer exists.
    // Done here, in the one path out of a task, rather than in the fault handler:
    // a task can also exit voluntarily while another task holds it on a queue it
    // registered for and then abandoned.
    if crate::ipc::forget_task(current_id()) > 0 {
        DIED_BLOCKED.fetch_add(1, Ordering::Relaxed);
    }

    let prev_ptr: *mut CpuContext;
    let next_ptr: *const CpuContext;
    let next_top: Option<u64>;
    let next_cr3: u64;
    let cpu = me();
    {
        let mut sched = SCHED.lock();
        let prev = sched.current[cpu];
        sched.tasks[prev].state = State::Dead;
        PREV[cpu].store(prev, Ordering::Relaxed);
        prev_ptr = &mut sched.tasks[prev].ctx;
        match sched.pick_next(prev) {
            Some(next) => {
                sched.tasks[next].state = State::Running;
                sched.current[cpu] = next;
                next_top = Some(sched.tasks[next].kernel_stack_top);
                next_cr3 = sched.tasks[next].cr3;
                next_ptr = &sched.tasks[next].ctx;
            }
            // Nothing left to run: back to the bootstrap context, which decides
            // whether the system is finished. The bootstrap runs in ring 0 and
            // makes no syscalls, so it needs no kernel stack installed — and
            // leaving the dead task's would be worse than leaving the last live
            // one's, since its stack is about to be freed.
            None => {
                sched.current[cpu] = NONE;
                next_top = None;
                // Back to the kernel's own tree. This task's is about to be torn
                // down, and the bootstrap context must not be the thing standing
                // in it when that happens.
                next_cr3 = KERNEL_ROOT.load(Ordering::SeqCst);
                next_ptr = &sched.bootstrap[cpu];
            }
        }
    }
    enter(next_top, Some(next_cr3));
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `prev` is a dead slot used only as a write sink for a context
    // nobody will load; `next` is a live context. Interrupts are masked.
    unsafe { context_switch(prev_ptr, next_ptr) };
    unreachable!("switched away from an exited task")
}

/// Settle the task this core just switched away from, and reclaim its stack if it
/// exited.
///
/// Runs immediately after every [`context_switch`] that resumes a *successor*,
/// and — for a task that has never run, which begins at its trampoline rather
/// than after a `context_switch` — from that trampoline via
/// [`staros_post_switch`], before the new task executes a line of its own code.
///
/// The freed `Box` is dropped *after* the scheduler lock is released, so the
/// heap's lock never nests underneath the scheduler's.
fn post_switch() {
    let prev = PREV[me()].swap(NONE, Ordering::Relaxed);
    if prev == NONE {
        return;
    }
    let (_freed, space) = {
        let mut sched = SCHED.lock();
        // Only a dead slot that still owns a stack is reapable, so a stray double
        // settle can never free the same allocation twice.
        let stack = if sched.tasks[prev].state == State::Dead
            && !sched.tasks[prev].stack.is_empty()
        {
            let old = core::mem::replace(
                &mut sched.tasks[prev].stack,
                Vec::<u64>::new().into_boxed_slice(),
            );
            REAPED_STACKS.fetch_add(1, Ordering::Relaxed);
            REAPED_WORDS.fetch_add(old.len() as u64, Ordering::Relaxed);
            Some(old)
        } else {
            None
        };
        // `take`, not a copy: a space handed out once can never be torn down
        // twice, whatever calls this.
        let space = if sched.tasks[prev].state == State::Dead {
            sched.tasks[prev].space.take()
        } else {
            None
        };
        // A dead task's capability table is heap the task no longer needs, and
        // dropping it is also what makes "granted" and "held" stop being the same
        // number at the end of a run. The capabilities themselves are values, not
        // authority — the authority is the object, and it outlives them.
        if sched.tasks[prev].state == State::Dead {
            sched.tasks[prev].caps = CapTable::new();
            sched.tasks[prev].mailbox = None;
        }
        (stack, space)
    };
    // `_freed` drops here, outside the scheduler lock.

    // And the dead task's address space, if it had one. Safe here and nowhere
    // earlier: the switch that brought this core here has already left that tree
    // — `enter` reloaded `CR3` before it — so the tables being freed are not the
    // ones the CPU is walking. Freeing them from inside the dying task would be a
    // fault with no report.
    if let Some(space) = space {
        // SAFETY: this core is no longer in that tree (see above), the space was
        // taken from the slot so nothing else holds it, and every frame it owns
        // came from `mem::alloc_frame` through its own mapping calls.
        let frames = unsafe { space.destroy() };
        REAPED_SPACES.fetch_add(1, Ordering::Relaxed);
        REAPED_FRAMES.fetch_add(frames as u64, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// The phase-2.4 self-test.
// ---------------------------------------------------------------------------

/// How many timer ticks each demonstration task runs for.
///
/// Thirty at 100 Hz is 300 ms — long enough that a preemption granularity of one
/// tick gives tens of switches, short enough not to be felt in a boot.
const RUN_TICKS: u64 = 30;

/// How often a task says something, in ticks. Three or four lines each, which is
/// enough to see the two of them alternating in the log and few enough that the
/// log is still a log.
const SAY_EVERY: u64 = 10;

/// Each task's own progress counter. Bumped once per iteration of its loop; the
/// absolute value is meaningless, the fact that it *moves* is not.
static PROGRESS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// How many times each task noticed the other one had advanced since it last
/// looked.
///
/// This is the criterion, and the reason the test is a test. Two tasks that never
/// yield will both finish whether or not preemption works — one after the other,
/// if it does not. What only preemption can produce is *this*: task A, while A is
/// running, observing that B has moved. That can happen only if B ran in between,
/// and nothing in either task's body asked for that to happen.
static ALTERNATIONS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// How many tasks reached the end of their body.
static FINISHED: AtomicU64 = AtomicU64::new(0);

/// The demonstration task bodies. Two `extern "C" fn` items rather than one with
/// an argument, because a task entry takes none — the trampoline has nowhere to
/// put it.
extern "C" fn task_a() {
    demo(0, "A");
}
extern "C" fn task_b() {
    demo(1, "B");
}

/// Spin for [`RUN_TICKS`] ticks, watching the other task, and return.
///
/// Returning is the point: the trampoline turns that into a call to
/// `staros_task_exit`, which is how a kernel thread's death is exercised without
/// anything in the task body knowing the scheduler exists.
fn demo(me: usize, name: &'static str) {
    let other = 1 - me;
    let start = crate::irq::ticks();
    let mut said = 0u64;
    let mut last_seen = PROGRESS[other].load(Ordering::Relaxed);

    loop {
        let elapsed = crate::irq::ticks().saturating_sub(start);
        if elapsed >= RUN_TICKS {
            break;
        }
        PROGRESS[me].fetch_add(1, Ordering::Relaxed);

        let now = PROGRESS[other].load(Ordering::Relaxed);
        if now != last_seen {
            last_seen = now;
            ALTERNATIONS[me].fetch_add(1, Ordering::Relaxed);
        }

        if elapsed / SAY_EVERY > said {
            said = elapsed / SAY_EVERY;
            // Through the locked console. This line and the other task's are what
            // the lock is for: without it the timer lands in the middle of one of
            // them and the two come out interleaved character by character.
            kprintln!(
                "task {name}: {} ticks in, {} steps, saw the other move {} times",
                elapsed,
                PROGRESS[me].load(Ordering::Relaxed),
                ALTERNATIONS[me].load(Ordering::Relaxed),
            );
        }
    }

    FINISHED.fetch_add(1, Ordering::Relaxed);
    kprintln!("task {name}: done after {} steps", PROGRESS[me].load(Ordering::Relaxed));
}

/// Run two tasks under preemption and check that they interleaved.
///
/// The criterion phase 2.4 names, and what each part of it rules out:
///
/// - **both finished** — the switch restores enough state that a task survives
///   being taken off the CPU and put back. A wrong offset in `__context_switch`
///   fails here, loudly, as a fault on a resumed task.
/// - **both saw the other advance** — they genuinely alternated. Neither body
///   yields, so the only thing that can have moved them is the timer.
/// - **preemptions happened** — the switches were driven by the IRQ epilogue and
///   not by something else.
/// - **both stacks were reaped** — a task's 32 KiB came back. Without
///   [`post_switch`] every kernel thread would leak its stack until reboot, and
///   nothing in the boot would look any different.
///
/// # Safety
/// Called once, on the boot core, after the timer has been calibrated. Enables
/// interrupts for its duration and masks them again before returning.
pub unsafe fn selftest(console: &mut Console) -> bool {
    use core::fmt::Write;

    if !spawn("A", task_a) || !spawn("B", task_b) {
        let _ = writeln!(console, "sched SELF-TEST FAILED: could not spawn two tasks");
        return false;
    }
    let _ = writeln!(
        console,
        "sched: {} tasks, {} KiB of kernel stack each, round robin",
        task_count(),
        STACK_WORDS * 8 / 1024,
    );

    // SAFETY: the timer is calibrated and its vector is the only unmasked source;
    // the caller guarantees the APICs are up.
    let Ok(hz) = (unsafe { crate::irq::start_ticking() }) else {
        let _ = writeln!(console, "sched SELF-TEST FAILED: the timer would not start");
        return false;
    };
    let _ = writeln!(
        console,
        "sched: preempting at {hz} Hz, each task runs for {RUN_TICKS} ticks and exits"
    );

    start();

    // SAFETY: nothing after this expects to be interrupted.
    unsafe { crate::irq::stop_ticking() };

    let finished = FINISHED.load(Ordering::Relaxed);
    let (switches, preemptions, _) = switch_counts();
    let (stacks, bytes) = reaped_stacks();
    let alternations = [
        ALTERNATIONS[0].load(Ordering::Relaxed),
        ALTERNATIONS[1].load(Ordering::Relaxed),
    ];
    let progress = [
        PROGRESS[0].load(Ordering::Relaxed),
        PROGRESS[1].load(Ordering::Relaxed),
    ];

    let _ = writeln!(
        console,
        "sched: {switches} switches ({preemptions} forced by the timer), \
         {finished} of 2 tasks finished"
    );
    let _ = writeln!(
        console,
        "sched: A took {} steps and saw B move {} times; B took {} steps and saw A move {} times",
        progress[0], alternations[0], progress[1], alternations[1],
    );
    let _ = writeln!(
        console,
        "sched: {stacks} dead stacks reaped, {} KiB returned to the heap",
        bytes / 1024,
    );
    describe(console);

    let mut ok = true;
    if finished != 2 {
        let _ = writeln!(
            console,
            "sched SELF-TEST FAILED: {finished} of 2 tasks reached the end of their body"
        );
        ok = false;
    }
    if preemptions == 0 {
        let _ = writeln!(
            console,
            "sched SELF-TEST FAILED: no switch was forced by the timer - \
             the tick is not reaching the IRQ epilogue"
        );
        ok = false;
    }
    if alternations[0] == 0 || alternations[1] == 0 {
        // The one failure the other three cannot catch: both tasks ran to
        // completion, one strictly after the other, and nothing preempted
        // anything. A log that only counted finished tasks would call that a pass.
        let _ = writeln!(
            console,
            "sched SELF-TEST FAILED: the tasks did not interleave - \
             each ran to completion before the other started"
        );
        ok = false;
    }
    let wanted_stacks = 2;
    if stacks != wanted_stacks {
        let _ = writeln!(
            console,
            "sched SELF-TEST FAILED: {stacks} of {wanted_stacks} dead stacks were reclaimed - \
             a kernel thread's stack is leaking until reboot"
        );
        ok = false;
    }
    ok
}
