//! The lock, arriving one architecture later than it did on aarch64.
//!
//! The counterpart of `../../../kernel-Aarch64/crates/kernel/src/sync.rs`, and the
//! same ticket lock for the same two reasons — fairness under contention, and
//! the fact that a lock an interrupt handler may touch has to be taken with
//! interrupts masked or a single core deadlocks against itself.
//!
//! It is here now rather than at phase 4 because the global allocator needs it:
//! `GlobalAlloc` is a `Sync` trait, so the free list has to be behind something
//! that makes shared access sound, and "there is only one core" is a comment,
//! not a type.
//!
//! The one difference from the aarch64 version is what masking means. There it
//! is `DAIF`; here it is `RFLAGS.IF`, saved and restored through
//! [`cpu::irq_save`] and [`cpu::irq_restore`] so releasing a lock cannot
//! *enable* interrupts inside a caller that had deliberately masked them.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use staros_arch_x86_64::cpu;

/// A ticket spinlock that also masks interrupts on the holding core.
pub struct SpinLock<T> {
    /// The next ticket to hand out.
    next: AtomicU32,
    /// The ticket currently being served.
    serving: AtomicU32,
    data: UnsafeCell<T>,
}

// SAFETY: the lock is what makes `&T` from multiple cores sound — access to the
// data is only ever handed out through a guard, and only one guard exists at a
// time. `T: Send` because the value is effectively moved between cores.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: as above; sending the lock itself sends the data.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Wrap `data` in a lock.
    pub const fn new(data: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Take the lock, masking interrupts on this core until the guard is dropped.
    pub fn lock(&self) -> SpinGuard<'_, T> {
        // Mask *first*. Taking the ticket and then being interrupted into
        // something that wants this lock would deadlock this core against itself.
        // SAFETY: the guard restores the previous state on drop, on this core.
        let irq = unsafe { cpu::irq_save() };
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        SpinGuard { lock: self, irq }
    }
}

/// Proof that this core holds the lock, and the only way to the data.
pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
    /// Whether interrupts were enabled before the lock was taken.
    irq: bool,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard's existence means this core is being served, so no
        // other guard for this lock exists.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` means no other borrow through this
        // guard is live either.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        // Release ordering: everything this core wrote under the lock must be
        // visible to the next core *before* it sees its ticket come up.
        self.lock.serving.fetch_add(1, Ordering::Release);
        // SAFETY: restores this core's interrupt state to what `lock` saved.
        unsafe { cpu::irq_restore(self.irq) };
    }
}
