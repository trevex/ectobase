use parking_lot::Mutex;

use uuid::Uuid;

/// Authoritative control-plane state (BPF map projection added in Milestone 3).
#[derive(Default)]
pub struct State {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    uuid: Option<String>,
}

impl State {
    /// Idempotently initialize; returns the stable service uuid.
    pub fn initialize(&self) -> String {
        let mut g = self.inner.lock();
        g.uuid
            .get_or_insert_with(|| Uuid::new_v4().to_string())
            .clone()
    }

    /// Returns Some(uuid) if initialized.
    pub fn check_initialized(&self) -> Option<String> {
        self.inner.lock().uuid.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_is_idempotent_and_check_reflects_it() {
        let s = State::default();
        assert_eq!(s.check_initialized(), None);
        let u1 = s.initialize();
        let u2 = s.initialize();
        assert_eq!(u1, u2, "initialize must be idempotent");
        assert_eq!(s.check_initialized(), Some(u1));
    }
}
