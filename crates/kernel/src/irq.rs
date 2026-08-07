//! Device interrupts: bringing the 8259s somewhere harmless, and proving it.
//!
//! Everything up to phase 1.4 ran with interrupts masked, from `ExitBootServices`
//! to the last line of the boot. That was not caution — it was necessity. The
//! firmware leaves the 8259 pair enabled and delivering on vectors 0 through 15,
//! and those vectors belong to the CPU: 8 is `#DF`, 13 is `#GP`, 14 is `#PF`. An
//! `sti` before this module runs turns the first stray interrupt into a fault
//! report naming an exception that never happened, and sends whoever reads it
//! looking for a stack overflow that does not exist.
//!
//! So the pair is re-initialised onto vectors 32..48 and every line is masked.
//! Only after that is `sti` a thing this kernel may do.
//!
//! ## Why a timer tick is the test
//! The 8259's initialisation words are write-only. The mask register reads back;
//! the vector base does not. There is no way to *ask* the chips where they are
//! delivering, so the only honest check is to make one interrupt happen and see
//! which vector it arrives on. The 8254 is the one device on a PC that can be
//! made to raise a real hardware interrupt with three `out` instructions, no
//! discovery and no ACPI — so the boot starts it, counts a few ticks, and stops
//! it again.
//!
//! Without the remap that same tick arrives as vector 8, and the boot ends in
//! `KERNEL FAULT: vector 8 - #DF double fault` instead. Which is exactly what
//! reverting the remap produces, and why this is asserted rather than assumed.
//!
//! ## What this is not
//! Not the kernel's interrupt controller. That is the local APIC, and it arrives
//! in phase 2.2 along with the I/O APIC and the MADT that describes them. The
//! 8259s will be masked for good then — but still remapped, because a masked
//! 8259 goes on emitting the occasional spurious interrupt and it has to land
//! somewhere that is not an exception vector.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use staros_arch_x86_64::pic::{self, Pic8259};
use staros_arch_x86_64::pit::Pit;
use staros_arch_x86_64::port::Ports;
use staros_arch_x86_64::{cpu, trap::TrapFrame};

use crate::console::Console;
use crate::sync::SpinLock;

/// First vector the 8259s deliver on.
///
/// 32 is the first vector the architecture does not reserve. Nothing below it is
/// available: vectors 0..31 are the CPU's exceptions, including the ones it has
/// not defined yet, which is why the range is reserved rather than merely used.
pub const PIC_BASE: u8 = 32;

/// The timer line, wired to the 8254's channel 0 on every PC.
pub const IRQ_TIMER: u8 = 0;

/// Rate the self-test runs the PIT at.
///
/// Fast enough that a handful of ticks is imperceptible, slow enough that the
/// divisor is nowhere near the ends of its range.
const SELFTEST_HZ: u32 = 1000;

/// How many ticks the self-test waits for.
///
/// More than one, because one tick proves delivery but not acknowledgement: a
/// missing EOI leaves the interrupt in service and the second tick never comes.
const SELFTEST_TICKS: u64 = 8;

/// How long to wait before giving up, in iterations of a spin loop.
///
/// A spin count rather than a deadline, because there is no clock yet — that is
/// what is being brought up. It has to be finite, or the test for "the interrupt
/// never arrives" is a hang rather than a test.
///
/// Sizing it is a real trade-off and it was got wrong first. Eight ticks at a
/// kilohertz is eight milliseconds of wall time, and under TCG emulation the
/// guest gets through perhaps a million iterations in that long — but the PIT is
/// driven by the *host* clock, so waiting is cheap and spinning is not. Twenty
/// million leaves two orders of magnitude of headroom for a slow emulator and
/// still gives up in a couple of seconds when nothing is coming.
const SELFTEST_PATIENCE: u64 = 20_000_000;

/// The 8259 pair.
static PIC: SpinLock<Pic8259<Ports>> = SpinLock::new(Pic8259::new(Ports));

/// The 8254.
static PIT: SpinLock<Pit<Ports>> = SpinLock::new(Pit::new(Ports));

/// Timer ticks seen since the PIT was started.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Interrupts that arrived on a line nothing had asked for.
static UNEXPECTED: AtomicU64 = AtomicU64::new(0);

/// Spurious interrupts the 8259s raised and then disowned.
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// Move the 8259s off the exception vectors and mask every line.
///
/// # Safety
/// Called once, on the boot core, with interrupts still masked. Reprogramming an
/// interrupt controller that is live is how an interrupt gets delivered halfway
/// through the reprogramming.
pub unsafe fn init(console: &mut Console) {
    let mut pic = PIC.lock();
    pic.remap(PIC_BASE);
    let masks = pic.masks();
    // Reported from the driver's own record of where it put them, not from the
    // constant it was asked to use. The two differ exactly when the remap did
    // not happen, which is the case worth being able to see.
    let _ = writeln!(
        console,
        "pic: 8259 pair remapped to vectors {}..{}, masks {:#06x}",
        pic.base(),
        u16::from(pic.base()) + u16::from(pic::LINES),
        masks,
    );
    if masks != u16::MAX {
        // The one piece of the chips' state that can be read back, so it is.
        let _ = writeln!(console, "pic: WARNING - not every line came up masked");
    }
}

/// Whether `vector` belongs to the 8259s.
#[must_use]
pub const fn is_device_vector(vector: u64) -> bool {
    vector >= PIC_BASE as u64 && vector < PIC_BASE as u64 + pic::LINES as u64
}

/// Handle a device interrupt. Called from the trap dispatcher.
///
/// Returns without acknowledging anything it does not recognise as real: a
/// spurious interrupt has nothing in service behind it, and an EOI for it would
/// clear the in-service bit of a genuine interrupt pending underneath.
pub fn dispatch(frame: &TrapFrame) {
    let irq = (frame.vector - PIC_BASE as u64) as u8;
    let mut pic = PIC.lock();

    if pic.is_spurious(irq) {
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        pic.end_of_spurious(irq);
        return;
    }

    match irq {
        IRQ_TIMER => {
            TICKS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            // Nothing else is unmasked, so this cannot happen — which is why it
            // is counted rather than ignored. A line that fires without being
            // asked to is a fact about the machine worth having.
            UNEXPECTED.fetch_add(1, Ordering::Relaxed);
        }
    }
    pic.end_of_interrupt(irq);
}

/// Enable interrupts for the first time, and prove the remap took by taking one.
///
/// The sequence matters and is the whole test:
///
/// 1. start the PIT, which begins pulling IRQ 0 immediately;
/// 2. unmask IRQ 0 and `sti` — the first moment this kernel has ever run with
///    interrupts enabled;
/// 3. spin until the tick count moves, or patience runs out;
/// 4. mask, stop, `cli`, and say what happened.
///
/// Step 3 is bounded rather than open-ended because the failure being tested for
/// is precisely "the interrupt never arrives", and a test for a missing interrupt
/// that waits forever is a hang, not a test.
///
/// Returns whether the ticks arrived, so the boot does not go on to claim a phase
/// it did not finish.
pub fn selftest(console: &mut Console) -> bool {
    let expected_vector = PIC.lock().vector_for(IRQ_TIMER);
    let hz = PIT.lock().start(SELFTEST_HZ);
    let _ = writeln!(
        console,
        "pit: channel 0 at {hz} Hz on IRQ {IRQ_TIMER}, expecting vector {expected_vector}"
    );

    TICKS.store(0, Ordering::SeqCst);
    PIC.lock().unmask(IRQ_TIMER);

    // SAFETY: the IDT has been installed since phase 1.3, the 8259s are remapped
    // clear of the exception vectors, and every line but this one is masked.
    unsafe { cpu::enable_interrupts() };

    let mut spins = 0u64;
    while TICKS.load(Ordering::Relaxed) < SELFTEST_TICKS && spins < SELFTEST_PATIENCE {
        core::hint::spin_loop();
        spins += 1;
    }

    // SAFETY: nothing after this expects to be interrupted; phase 2.2 is what
    // turns interrupts on for good, once there is a controller worth listening to.
    unsafe { cpu::disable_interrupts() };
    PIC.lock().mask(IRQ_TIMER);
    PIT.lock().stop();

    let ticks = TICKS.load(Ordering::SeqCst);
    let spurious = SPURIOUS.load(Ordering::SeqCst);
    let unexpected = UNEXPECTED.load(Ordering::SeqCst);

    let passed = ticks >= SELFTEST_TICKS;
    if passed {
        let _ = writeln!(
            console,
            "irq: {ticks} timer interrupts delivered on vector {expected_vector} and acknowledged"
        );
    } else {
        // Either the remap did not take, or the EOI is wrong. The count says
        // which: zero means nothing was ever delivered here, and one means the
        // first was delivered and never acknowledged.
        let _ = writeln!(
            console,
            "irq SELF-TEST FAILED: {ticks} of {SELFTEST_TICKS} timer interrupts arrived"
        );
        let _ = writeln!(
            console,
            "  {}",
            if ticks == 0 {
                "none at all - the vectors are not where this kernel thinks they are"
            } else {
                "delivery works, acknowledgement does not - the PIC is still holding the line"
            }
        );
    }
    if spurious > 0 || unexpected > 0 {
        let _ = writeln!(
            console,
            "irq: {spurious} spurious, {unexpected} on lines nothing asked for"
        );
    }
    let _ = writeln!(console, "irq: interrupts masked again until the APIC is up");
    passed
}
