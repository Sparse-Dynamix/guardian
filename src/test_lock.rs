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

#[cfg(test)]
mod tests {
    use super::env_test_lock;

    #[test]
    fn env_test_lock_recovers_after_poison() {
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = env_test_lock();
            panic!("poison lock");
        });
        assert!(poisoned.is_err());
        let _guard = env_test_lock();
    }

    #[test]
    fn env_test_lock_can_be_acquired() {
        let _guard = env_test_lock();
    }
}
