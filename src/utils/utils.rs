use spin::Mutex;
use x86_64::instructions::interrupts;

pub struct IrqSafeMutex<T> {
    inner: Mutex<T>,
}

impl<T> IrqSafeMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    pub fn lock(&self) -> IrqSafeMutexGuard<'_, T> {
        // disable interrupts BEFORE acquiring the lock
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();

        let guard = self.inner.lock();

        IrqSafeMutexGuard {
            guard,
            was_enabled,
        }
    }
}

pub struct IrqSafeMutexGuard<'a, T> {
    guard: spin::MutexGuard<'a, T>,
    was_enabled: bool,
}

impl<'a, T> Drop for IrqSafeMutexGuard<'a, T> {
    fn drop(&mut self) {
        // drop the inner guard first
        let _ = &mut self.guard;

        // then re-enable interrupts if they were enabled before
        if self.was_enabled {
            interrupts::enable();
        }
    }
}

impl<'a, T> core::ops::Deref for IrqSafeMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> core::ops::DerefMut for IrqSafeMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

unsafe impl<T: Send> Send for IrqSafeMutex<T> {}
unsafe impl<T: Send> Sync for IrqSafeMutex<T> {}