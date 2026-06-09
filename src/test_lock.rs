//! Serializes unit tests that mutate process-global environment or working directory.

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

#[cfg(test)]
static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn env_test_lock() -> MutexGuard<'static, ()> {
    ENV_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
