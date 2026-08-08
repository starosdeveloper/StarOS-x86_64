//! Bringing up the CPU tables, and what the kernel does when something faults.
//!
//! The arch crate owns the mechanism — the descriptors, the entry stubs, the
//! saved frame. This is the policy: which faults are survivable, what a report
//! says, and where it goes.
//!
//! Today exactly two faults are survivable, and both of them are the boot's own
//! self-test. Everything else stops the core, because nothing in this kernel can
//! yet *do* anything about a fault: there is no page table of its own to fix up,
//! no process to kill, no scheduler to run something else. Pretending otherwise
//! would mean continuing with an invariant already known to be false.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use staros_arch_x86_64::trap::{PageFaultCause, TrapFrame};
use staros_arch_x86_64::{cpu, gdt, idt, selftest, trap};

use crate::console::{self, Console};

/// Vector numbers this module reasons about by name.
const VECTOR_BREAKPOINT: u64 = 3;
const VECTOR_DOUBLE_FAULT: u64 = 8;
const VECTOR_PAGE_FAULT: u64 = 14;

/// Where the page-fault self-test wants execution to continue, or zero when no
/// self-test is in flight.
///
/// A non-zero value here is the *only* licence the handler has to resume from a
/// page fault, and it is cleared the moment it is honoured — so a second fault
/// at the same address is fatal, as a real one would be.
static RESUME_AT: AtomicU64 = AtomicU64::new(0);

/// The address the armed self-test expects to fault on.
static EXPECT_FAULT_AT: AtomicU64 = AtomicU64::new(0);

/// Whether a self-test is armed at all. Separate from the address, because zero
/// became a legitimate address to expect a fault at the moment the kernel
/// stopped identity-mapping it.
static ARMED: AtomicBool = AtomicBool::new(false);

/// One past the last user address. Everything below the canonical hole.
const USER_LIMIT: u64 = 0x0000_8000_0000_0000;

unsafe extern "C" {
    /// First byte of the stack guard page, from `crates/arch-x86_64/linker.ld`.
    static __stack_guard: u8;
    /// First byte of the usable boot stack, one page above the guard.
    static __stack_bottom: u8;
}

/// Install the GDT, the TSS and the IDT, and register the handler below.
///
/// Order is not a preference: the IDT's gates name the kernel code selector, so
/// the GDT that defines it has to be loaded first. Both happen with interrupts
/// still masked, as the loader left them.
///
/// # Safety
/// Called once, on the boot core, before interrupts are unmasked.
pub unsafe fn init() {
    // SAFETY: first and only call, interrupts masked.
    unsafe { gdt::install() };
    // SAFETY: the GDT above is loaded, which is what the gates reference.
    unsafe { idt::install() };
    trap::set_handler(on_trap);
}

/// Report the tables that are now live.
pub fn describe(console: &mut Console) {
    let _ = writeln!(
        console,
        "gdt: loaded, kernel cs {:#04x} ss {:#04x}, tss {:#04x}",
        gdt::KERNEL_CODE,
        gdt::KERNEL_DATA,
        gdt::TSS_SELECTOR,
    );
    let _ = writeln!(
        console,
        "idt: {} vectors, separate stacks for #DF, NMI and #MC",
        idt::VECTORS,
    );
}

/// Every trap arrives here.
fn on_trap(frame: &mut TrapFrame) {
    // First, before anything else can fault: CR2 is overwritten by the next page
    // fault, including one taken inside this handler.
    let faulting_address = cpu::read_cr2();

    // Device interrupts first, and without touching the console. They are the
    // only traps here that are not a diagnosis: a timer tick is routine, it can
    // arrive thousands of times a second, and printing a line for each one would
    // turn a working interrupt controller into a machine that does nothing but
    // describe itself.
    if crate::irq::is_device_vector(frame.vector) {
        crate::irq::dispatch(frame);
        return;
    }

    let Some(mut handle) = console::get() else {
        // A trap between `lidt` and the console existing. There is nowhere to
        // say so, and continuing would be a guess.
        cpu::halt()
    };
    let console = &mut handle;

    // The two survivable paths print through the ordinary, locked console: they
    // return to the code that was interrupted, so their lines have to take their
    // turn like anyone else's. Both run during a self-test on the boot path,
    // where nothing else is printing anyway.
    if resume_if_expected(console, frame, faulting_address) {
        return;
    }
    if frame.vector == VECTOR_BREAKPOINT {
        let _ = writeln!(console, "trap: #BP at RIP={:#x}, resuming", frame.rip);
        return;
    }

    // A fault in ring 3 is not the kernel's failure, and this is the first phase
    // in which that distinction exists. The task that took it is killed; the
    // kernel keeps running. `sched::exit` never returns, so the trap frame under
    // us is abandoned along with the stack it sits on — which is correct, because
    // that stack belongs to the task being destroyed and its successor reclaims it.
    if frame.from_user() && crate::sched::in_task() {
        report_user(console, frame, faulting_address);
        crate::usermode::note_user_fault();
        crate::sched::exit()
    }

    report(frame, faulting_address);
    cpu::halt()
}

/// Honour an armed self-test resume, if this trap is the one that was armed.
///
/// Returns whether the trap was consumed.
fn resume_if_expected(console: &mut Console, frame: &mut TrapFrame, address: u64) -> bool {
    if !ARMED.load(Ordering::SeqCst)
        || frame.vector != VECTOR_PAGE_FAULT
        || RESUME_AT.load(Ordering::SeqCst) == 0
    {
        return false;
    }
    if address != EXPECT_FAULT_AT.load(Ordering::SeqCst) {
        // Armed, but this is not the fault that was armed for. Falling through
        // to the fatal path is the point: a self-test must not turn an unrelated
        // page fault into a silent resume.
        return false;
    }
    let resume = RESUME_AT.swap(0, Ordering::SeqCst);
    ARMED.store(false, Ordering::SeqCst);
    let cause = PageFaultCause::from_error_code(frame.error_code);
    let _ = writeln!(
        console,
        "trap: #PF at {:#x}, RIP={:#x}, err={:#x} ({}{}), resuming at {:#x}",
        address,
        frame.rip,
        frame.error_code,
        cause.as_str(),
        if smap_suspected(address, cause) { ", supervisor access to a user page - SMAP" } else { "" },
        resume,
    );
    // The whole point of the exercise: `iretq` reloads RIP from the frame, so
    // writing it here steps over the instruction that faulted.
    frame.rip = resume;
    true
}

/// Report a fault taken in ring 3, which ends a task and nothing else.
///
/// Through the ordinary, locked console rather than [`console::emergency`], and
/// the difference is the whole point: the kernel survives this, so the report has
/// to take its turn in the log like every other message. The emergency path exists
/// for reports that are the last thing a core will ever print, and this is not one.
///
/// `CS` is printed because it is the evidence. A `#GP` from a bad `sysret` looks
/// identical to a `#GP` from bad user code *except* in which ring took it, and
/// getting that wrong is the escalation `staros_arch_x86_64::syscall` exists to
/// prevent.
fn report_user(console: &mut Console, frame: &TrapFrame, address: u64) {
    let _ = writeln!(
        console,
        "user fault: task \"{}\" took vector {} - {} in ring {}",
        crate::sched::current_name(),
        frame.vector,
        trap::vector_name(frame.vector),
        if frame.from_user() { 3 } else { 0 },
    );
    let _ = writeln!(
        console,
        "  RIP={:#018x} CS={:#06x} RSP={:#018x} SS={:#06x} error={:#x}",
        frame.rip, frame.cs, frame.rsp, frame.ss, frame.error_code,
    );
    if frame.vector == VECTOR_PAGE_FAULT {
        let cause = PageFaultCause::from_error_code(frame.error_code);
        let _ = writeln!(console, "  #PF at {:#x}: {}", address, cause.as_str());
    }
    let _ = writeln!(console, "  killing the task; the kernel continues");
}

/// Print everything known about a fault that ends the boot.
///
/// Through [`console::emergency`], not the ordinary console. This report is the
/// last thing this core will print, and the code it interrupted may be holding
/// the console lock — waiting for a lock whose holder is never going to run again
/// would eat exactly the message worth keeping. See `console`'s module docs.
fn report(frame: &TrapFrame, address: u64) {
    // SAFETY: a trap has suspended every other writer on this core, and this
    // kernel has one core. Nothing after this call runs.
    let mut console = unsafe { console::emergency() };
    let console = &mut console;
    console.set_alert(true);
    let _ = writeln!(
        console,
        "\nKERNEL FAULT: vector {} - {}",
        frame.vector,
        trap::vector_name(frame.vector),
    );
    let _ = writeln!(
        console,
        "  RIP={:#018x} CS={:#06x} RFLAGS={:#x}",
        frame.rip, frame.cs, frame.rflags,
    );
    let _ = writeln!(
        console,
        "  RSP={:#018x} SS={:#06x} error={:#x} ring={}",
        frame.rsp,
        frame.ss,
        frame.error_code,
        if frame.from_user() { 3 } else { 0 },
    );

    if frame.vector == VECTOR_PAGE_FAULT {
        let cause = PageFaultCause::from_error_code(frame.error_code);
        let _ = writeln!(console, "  #PF at {:#x}: {}", address, cause.as_str());
        if smap_suspected(address, cause) {
            // The error code cannot say this on its own: a SMAP violation and a
            // write to a read-only page produce the same five bits. What
            // separates them is that the target is a user address and the access
            // was not.
            let _ = writeln!(console, "  a supervisor access to a user address - SMAP, or a stray user pointer");
        }
    }
    if frame.vector == VECTOR_DOUBLE_FAULT {
        // A #DF only says "a fault happened while delivering a fault". CR2 still
        // holds the address of the first one, which is what actually explains it.
        let _ = writeln!(console, "  the first fault was at {address:#x}");
        if in_stack_guard(address) {
            let _ = writeln!(
                console,
                "  that is the kernel stack guard page: the stack overflowed"
            );
        }
    }
    let _ = writeln!(console, "  halting - this core cannot continue");
    console.set_alert(false);
}

/// Whether a fault looks like SMEP or SMAP rather than an ordinary permission
/// error: a present page, a supervisor access, and a user-half address.
fn smap_suspected(address: u64, cause: PageFaultCause) -> bool {
    cause.protection_violation && !cause.user && address < USER_LIMIT
}

/// Arm the handler to survive one page fault at `address`.
///
/// Returns the slot the faulting code must write its resume address into. The
/// two halves are separate because only the faulting code knows where its own
/// instruction ends.
#[must_use]
pub fn arm_page_fault(address: u64) -> *mut u64 {
    EXPECT_FAULT_AT.store(address, Ordering::SeqCst);
    RESUME_AT.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    RESUME_AT.as_ptr()
}

/// Disarm, whether or not the expected fault arrived.
pub fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
    RESUME_AT.store(0, Ordering::SeqCst);
    EXPECT_FAULT_AT.store(0, Ordering::SeqCst);
}

/// Whether the armed fault has been consumed.
#[must_use]
pub fn fault_was_taken() -> bool {
    !ARMED.load(Ordering::SeqCst)
}

/// Whether `address` lies in the boot stack's guard page.
///
/// The guard is one page that no `PT_LOAD` segment covers, so the loader never
/// maps it; the symbols around it come from the linker script, which is the only
/// place that knows where it is.
fn in_stack_guard(address: u64) -> bool {
    let guard = &raw const __stack_guard as u64;
    let bottom = &raw const __stack_bottom as u64;
    (guard..bottom).contains(&address)
}

/// Take two survivable faults on purpose, and check that both came back.
///
/// This is the falsifiable half of phase 1.3. The pair is chosen deliberately:
/// `int3` is a vector with no error code and `#PF` is one with, so between them
/// they exercise both shapes of stub. If the dummy-push logic were inverted, one
/// of the two would report a vector one word away from the right one and the
/// resume would land in the middle of an instruction.
///
/// It also exercises the *return* path through `iretq`, which nothing else in
/// the kernel reaches until there is a timer.
///
/// The address read is the stack guard page, not zero. Zero is identity-mapped
/// by the loader until phase 1.4 builds the kernel's own tables, so a null
/// dereference here reads real memory and faults on nothing. The guard page is
/// the one address this kernel can point at today and be certain nothing maps
/// it — and reading it also proves the guard is genuinely absent from the page
/// tables, which is the assumption the double-fault test below rests on.
pub fn selftest_recoverable(console: &mut Console) {
    let _ = writeln!(console, "trap self-test: int3");
    selftest::breakpoint();

    let guard = &raw const __stack_guard as u64;
    let _ = writeln!(console, "trap self-test: reading the unmapped guard page at {guard:#x}");
    let slot = arm_page_fault(guard);
    // SAFETY: the IDT is installed and `on_trap` resumes at `*slot` for a page
    // fault at exactly this address, which is what this is about to cause.
    unsafe { selftest::read_unmapped(guard, slot) };
    disarm();

    let _ = writeln!(console, "trap self-test: both traps returned to their caller");
}

/// Overflow the kernel stack, and never come back.
///
/// The last thing the boot does, because it is the one self-test that cannot be
/// survived: it ends on the IST stack with a `#DF` report. Without a working
/// TSS and IST it ends as a triple fault instead, which on QEMU is a line in
/// `-d guest_errors` and on real firmware is a reboot.
///
/// # Safety
/// Destroys the current stack. Never returns.
pub unsafe fn selftest_stack_guard(console: &mut Console) -> ! {
    let guard = &raw const __stack_guard as u64;
    let _ = writeln!(
        console,
        "trap self-test: overflowing the kernel stack into its guard page at {guard:#x}",
    );
    // SAFETY: forwarded from this function's contract.
    unsafe { selftest::overflow_the_stack() }
}
