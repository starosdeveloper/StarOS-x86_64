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
//! ## And then the real controller
//! Phase 2.2 brings up the APICs, and the 8259s stay masked for good — but still
//! remapped, because a masked 8259 goes on emitting the occasional spurious
//! interrupt and it has to land somewhere that is not an exception vector.
//!
//! The APIC path is checked the same way and for the same reason: by making one
//! interrupt happen. What it proves is different, though. The 8259 test proved
//! *where* interrupts arrive; this one proves the route was read rather than
//! guessed. The I/O APIC has one redirection entry per **global system
//! interrupt**, and legacy IRQ numbers map onto GSIs by a table the firmware
//! publishes, not by identity — on nearly every PC the timer's IRQ 0 arrives as
//! GSI 2, because the 8259 cascade line took GSI 0 first. Program entry 0 for the
//! timer and the line is configured for something that is not there.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use staros_arch_x86_64::apic::{self, IoApic, LocalApic, Redirection};
use staros_arch_x86_64::mmio::MappedRegisters;
use staros_arch_x86_64::pic::{self, Pic8259};
use staros_arch_x86_64::pit::Pit;
use staros_arch_x86_64::port::Ports;
use staros_arch_x86_64::{cpu, trap::TrapFrame};

use crate::acpi::Facts;
use crate::console::Console;
use crate::sync::SpinLock;
use crate::vm::Tables;

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

/// Vector the timer arrives on once the I/O APIC is routing it.
///
/// Above the 8259 range on purpose. The chips stay remapped and masked, and a
/// masked 8259 still emits the occasional spurious interrupt; if the APIC's
/// vectors overlapped theirs, one of those would be indistinguishable from a real
/// device interrupt.
pub const APIC_TIMER_VECTOR: u8 = 48;

/// Vector the local APIC raises when an interrupt is withdrawn between the
/// request and the acknowledge.
///
/// Conventionally 255, and conventionally the highest vector for a reason: on
/// some older parts the low four bits of this register are read-only and read as
/// ones, so a vector whose low nibble is not `0xF` is silently rounded up to one
/// that is. Choosing `0xFF` makes the hardware's preference and the kernel's
/// agree.
pub const APIC_SPURIOUS_VECTOR: u8 = 255;

/// The 8259 pair.
static PIC: SpinLock<Pic8259<Ports>> = SpinLock::new(Pic8259::new(Ports));

/// The 8254.
static PIT: SpinLock<Pit<Ports>> = SpinLock::new(Pit::new(Ports));

/// The local APIC, once its registers have been mapped.
static LAPIC: SpinLock<Option<LocalApic<MappedRegisters>>> = SpinLock::new(None);

/// The first I/O APIC, once its registers have been mapped.
static IOAPIC: SpinLock<Option<IoApic<MappedRegisters>>> = SpinLock::new(None);

/// Which controller is delivering: the 8259s until the APICs are up.
///
/// Read by the trap dispatcher on every interrupt, which is why it is an atomic
/// rather than something behind a lock — a lock taken on every interrupt to
/// decide *how to acknowledge* would be the first thing to deadlock.
static USING_APIC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The vector the timer currently arrives on, whichever controller is routing it.
static TIMER_VECTOR: AtomicU8 = AtomicU8::new(PIC_BASE + IRQ_TIMER);

/// Spurious interrupts the local APIC raised.
static APIC_SPURIOUS: AtomicU64 = AtomicU64::new(0);

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

/// Whether `vector` is one a device can arrive on rather than an exception.
///
/// Everything from the 8259 base upwards. The range has to include the APIC's
/// vectors as well as the chips', because both can deliver during bring-up and a
/// vector that fell outside this test would be reported as a fatal fault.
#[must_use]
pub const fn is_device_vector(vector: u64) -> bool {
    vector >= PIC_BASE as u64 && vector < 256
}

/// Handle a device interrupt. Called from the trap dispatcher.
///
/// Which controller gets acknowledged is decided here rather than by the caller,
/// because the answer changes halfway through the boot: the 8259s deliver until
/// the APICs are up, and acknowledging the wrong one leaves the real one holding
/// the line.
pub fn dispatch(frame: &TrapFrame) {
    if USING_APIC.load(Ordering::Relaxed) {
        dispatch_apic(frame);
    } else {
        dispatch_pic(frame);
    }
}

/// The 8259 path.
///
/// Returns without acknowledging anything it does not recognise as real: a
/// spurious interrupt has nothing in service behind it, and an EOI for it would
/// clear the in-service bit of a genuine interrupt pending underneath.
fn dispatch_pic(frame: &TrapFrame) {
    let Some(irq) = u8::try_from(frame.vector - PIC_BASE as u64).ok().filter(|i| *i < pic::LINES)
    else {
        UNEXPECTED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let mut pic = PIC.lock();

    if pic.is_spurious(irq) {
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        pic.end_of_spurious(irq);
        return;
    }

    if irq == IRQ_TIMER {
        TICKS.fetch_add(1, Ordering::Relaxed);
    } else {
        // Nothing else is unmasked, so this cannot happen — which is why it is
        // counted rather than ignored. A line that fires without being asked to
        // is a fact about the machine worth having.
        UNEXPECTED.fetch_add(1, Ordering::Relaxed);
    }
    pic.end_of_interrupt(irq);
}

/// The APIC path.
///
/// Shorter than the 8259 one, and the difference is the point. There is no
/// controller to ask what happened: the vector *is* the answer, decided when the
/// redirection entry was programmed. And the spurious vector is a vector like any
/// other rather than a state to interrogate — the local APIC raises it by name.
fn dispatch_apic(frame: &TrapFrame) {
    let vector = frame.vector as u8;

    if vector == APIC_SPURIOUS_VECTOR {
        // The one interrupt that must *not* be acknowledged: the APIC never
        // marked it in service, so an EOI would retire something else.
        APIC_SPURIOUS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if vector == TIMER_VECTOR.load(Ordering::Relaxed) {
        TICKS.fetch_add(1, Ordering::Relaxed);
    } else {
        UNEXPECTED.fetch_add(1, Ordering::Relaxed);
    }

    if let Some(lapic) = LAPIC.lock().as_mut() {
        lapic.end_of_interrupt();
    }
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

/// Bring up the local APIC and the I/O APIC, and hand the timer over to them.
///
/// The order is forced. The 8259s are masked for good *first*, because the two
/// controllers would otherwise both deliver the same line and the second copy
/// arrives on a vector nothing acknowledges. Then the local APIC — it is what
/// receives, so it has to be listening before anything is routed to it. Then the
/// I/O APIC, with every entry masked, because firmware left them pointing at
/// vectors that meant something under its own IDT.
///
/// # Errors
/// Returns a message when the machine cannot be brought up this way: no I/O APIC
/// in the MADT, or a GSI outside the controller's range. Both mean the boot must
/// say so rather than program an address it guessed.
///
/// # Safety
/// Called once, on the boot core, with interrupts masked, after `vm::init` and
/// [`init`].
pub unsafe fn init_apic(
    console: &mut Console,
    tables: &Tables,
    facts: &Facts,
) -> Result<(), &'static str> {
    // The 8259s stop delivering entirely. They stay remapped: a masked 8259 still
    // emits the occasional spurious interrupt, and it must not land on a vector
    // that means something else.
    PIC.lock().mask_all();

    // SAFETY: the MADT gave this address, nothing else has mapped it, and the
    // mapping is made uncacheable — see `vm::map_device`.
    let lapic_virt = unsafe { crate::vm::map_device(tables, facts.local_apic, 0x1000)? };
    // SAFETY: `lapic_virt` is the live device mapping just made, and this is the
    // only driver for it.
    let mut lapic = LocalApic::new(unsafe { MappedRegisters::new(lapic_virt) });

    // The hardware enable, in a model-specific register, is separate from the
    // software enable in the spurious-vector register. Firmware normally leaves
    // the first set; setting it again is harmless and removes the assumption.
    // SAFETY: ring 0; the base address is preserved and only the enable bit is
    // added, so the APIC does not move.
    unsafe {
        let base = cpu::read_msr(apic::IA32_APIC_BASE);
        cpu::write_msr(apic::IA32_APIC_BASE, base | apic::APIC_BASE_ENABLE);
    }
    lapic.enable(APIC_SPURIOUS_VECTOR);

    let id = lapic.id();
    let version = lapic.version();
    let enabled = lapic.is_enabled();
    let _ = writeln!(
        console,
        "lapic: id {id}, version {version:#04x}, {} lvt entries, spurious vector {}, {}",
        lapic.lvt_entries(),
        lapic.spurious_vector(),
        if enabled { "enabled" } else { "NOT ENABLED" },
    );
    *LAPIC.lock() = Some(lapic);
    if !enabled {
        return Err("the local APIC did not come up enabled");
    }

    let Some((io_phys, gsi_base)) = facts.io_apic else {
        return Err("the MADT declares no I/O APIC");
    };
    // SAFETY: as the local APIC above.
    let io_virt = unsafe { crate::vm::map_device(tables, io_phys, 0x20)? };
    // SAFETY: the live device mapping just made; single driver.
    let mut io = IoApic::new(unsafe { MappedRegisters::new(io_virt) }, gsi_base);
    io.mask_all();
    let _ = writeln!(
        console,
        "ioapic: id {}, version {:#04x}, {} entries covering gsi {}..{}",
        io.id(),
        io.version(),
        io.entry_count(),
        gsi_base,
        gsi_base + io.entry_count(),
    );
    *IOAPIC.lock() = Some(io);

    USING_APIC.store(true, Ordering::SeqCst);
    Ok(())
}

/// Route the timer through the I/O APIC and take eight ticks on it.
///
/// The falsifiable half of phase 2.2, and what it falsifies is a *guess*. The
/// redirection entry is chosen by asking the MADT which global system interrupt
/// IRQ 0 arrives on; on this machine the answer is 2, not 0, because the 8259
/// cascade line took GSI 0 first. Assume identity and the kernel programs a line
/// nothing is attached to — which produces no error, no fault, and no ticks.
///
/// Returns whether the ticks arrived.
///
/// # Safety
/// Called once, after [`init_apic`], with interrupts masked.
pub unsafe fn selftest_apic(console: &mut Console, facts: &Facts) -> bool {
    // SAFETY: the linear map is live and the MADT is where `discover` found it.
    let gsi = unsafe { facts.gsi_for_irq(IRQ_TIMER) };
    // SAFETY: as above.
    let flags = unsafe { facts.override_flags(IRQ_TIMER) };
    let (active_low, level) = apic::polarity_and_trigger(flags.unwrap_or(0));

    let _ = writeln!(
        console,
        "ioapic: irq {IRQ_TIMER} arrives on gsi {gsi} ({}), polarity {}, {} triggered",
        if gsi == u32::from(IRQ_TIMER) {
            "identity"
        } else {
            "remapped by the MADT - assuming identity would route the wrong line"
        },
        if active_low { "active low" } else { "active high" },
        if level { "level" } else { "edge" },
    );

    let destination = LAPIC.lock().as_mut().map_or(0, LocalApic::id);
    let entry = Redirection {
        vector: APIC_TIMER_VECTOR,
        destination,
        active_low,
        level_triggered: level,
        masked: false,
    };

    {
        let mut slot = IOAPIC.lock();
        let Some(io) = slot.as_mut() else {
            let _ = writeln!(console, "ioapic SELF-TEST FAILED: no controller");
            return false;
        };
        if !io.covers(gsi) {
            let _ = writeln!(
                console,
                "ioapic SELF-TEST FAILED: gsi {gsi} is outside this controller's range"
            );
            return false;
        }
        io.set_redirection(gsi, entry);
        // Read back rather than trust the write. These are indirect registers —
        // an index written to one port and a value to another — and a driver that
        // got the sequence wrong writes somewhere plausible and reports nothing.
        let back = io.redirection(gsi);
        if back != entry {
            let _ = writeln!(
                console,
                "ioapic SELF-TEST FAILED: entry read back as vector {} dest {} (masked {})",
                back.vector, back.destination, back.masked,
            );
            return false;
        }
    }

    TIMER_VECTOR.store(APIC_TIMER_VECTOR, Ordering::SeqCst);
    TICKS.store(0, Ordering::SeqCst);
    let hz = PIT.lock().start(SELFTEST_HZ);
    let _ = writeln!(
        console,
        "ioapic: gsi {gsi} -> vector {APIC_TIMER_VECTOR} on apic {destination}, pit at {hz} Hz"
    );

    // SAFETY: the IDT is installed, the 8259s are masked, the local APIC is
    // enabled with a spurious vector this kernel recognises, and exactly one
    // redirection entry is unmasked.
    unsafe { cpu::enable_interrupts() };

    let mut spins = 0u64;
    while TICKS.load(Ordering::Relaxed) < SELFTEST_TICKS && spins < SELFTEST_PATIENCE {
        core::hint::spin_loop();
        spins += 1;
    }

    // SAFETY: nothing after this expects to be interrupted; phase 2.3 turns them
    // on for good, once there is a timer worth listening to.
    unsafe { cpu::disable_interrupts() };
    if let Some(io) = IOAPIC.lock().as_mut() {
        io.set_masked(gsi, true);
    }
    PIT.lock().stop();

    let ticks = TICKS.load(Ordering::SeqCst);
    let passed = ticks >= SELFTEST_TICKS;
    if passed {
        let _ = writeln!(
            console,
            "irq: {ticks} timer interrupts delivered on vector {APIC_TIMER_VECTOR} \
             through the I/O APIC and acknowledged at the local APIC"
        );
    } else {
        let _ = writeln!(
            console,
            "irq SELF-TEST FAILED: {ticks} of {SELFTEST_TICKS} arrived through the I/O APIC"
        );
        let _ = writeln!(
            console,
            "  {}",
            if ticks == 0 {
                "none at all - the wrong GSI, a masked entry, or an APIC that is not listening"
            } else {
                "delivery works, acknowledgement does not - the local APIC is still in service"
            }
        );
    }
    let spurious = APIC_SPURIOUS.load(Ordering::SeqCst);
    let unexpected = UNEXPECTED.load(Ordering::SeqCst);
    if spurious > 0 || unexpected > 0 {
        let _ = writeln!(
            console,
            "irq: {spurious} spurious from the local APIC, {unexpected} on vectors nothing asked for"
        );
    }
    let _ = writeln!(console, "irq: interrupts masked again until there is a timer");
    passed
}
