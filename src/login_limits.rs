//! Bounded, process-local login admission and failure budgets.
//!
//! A source admission is consumed before database/password work. Account entries
//! are reserved before password work and record only failed proofs. Both kinds
//! share one hard capacity. Saturation rejects new identities without evicting
//! a live identity, since eviction would let random input reset its budget.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

// Upstream request validation is stricter; this defensive bound also limits
// hashing work if a future caller bypasses that validation.
const MAX_IDENTITY_BYTES: usize = 1024;
const CLEANUP_BATCH: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct LoginLimitOptions {
    /// Shared upper bound for source and account entries, including reservations.
    pub(crate) max_entries: usize,
    /// Fixed window, measured with a monotonic clock rather than wall time.
    pub(crate) ttl: Duration,
    pub(crate) source_limit: u32,
    pub(crate) user_failure_limit: u32,
}

trait Clock: Send + Sync {
    fn seconds(&self) -> u64;
}

struct MonotonicClock(Instant);

impl Clock for MonotonicClock {
    fn seconds(&self) -> u64 {
        self.0.elapsed().as_secs()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum IdentityKind {
    Source,
    Account,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key(IdentityKind, [u8; 32]);

struct Entry {
    count: u32,
    // u128 keeps even an injected u64::MAX clock plus its TTL representable.
    expires_at: u128,
}

#[derive(Default)]
struct Store {
    entries: HashMap<Key, Entry>,
    // Exactly one index item per entry; repeated requests never append tombstones.
    expirations: BTreeSet<(u128, Key)>,
    last_now: u64,
}

pub(crate) struct LoginLimits {
    options: LoginLimitOptions,
    ttl_seconds: u128,
    clock: Arc<dyn Clock>,
    store: Mutex<Store>,
}

impl LoginLimits {
    /// Invalid zero-valued budgets fail closed. Configuration validates them at
    /// startup, and keeping this constructor infallible avoids a panic fallback.
    pub(crate) fn new(options: LoginLimitOptions) -> Self {
        Self::with_clock(options, Arc::new(MonotonicClock(Instant::now())))
    }

    fn with_clock(options: LoginLimitOptions, clock: Arc<dyn Clock>) -> Self {
        let ttl_seconds =
            u128::from(options.ttl.as_secs()) + u128::from(options.ttl.subsec_nanos() != 0);
        Self {
            options,
            ttl_seconds,
            clock,
            store: Mutex::new(Store::default()),
        }
    }

    /// Consume one source admission. `Some(seconds)` means deny and retry later.
    /// Successful passwords do not replenish this budget.
    pub(crate) fn admit_source(&self, source: &str) -> Option<u64> {
        self.access(IdentityKind::Source, source, true)
    }

    /// Check an account's failures and reserve its slot before password work.
    /// Reservations prevent concurrent random unknown usernames from bypassing
    /// capacity by waiting until their password work has completed to insert.
    pub(crate) fn check_account(&self, account: &str) -> Option<u64> {
        self.access(IdentityKind::Account, account, false)
    }

    /// Record a failed proof. Callers must first use `check_account`; its return
    /// value also protects future callers if that reservation was not obtained.
    pub(crate) fn record_failure(&self, account: &str) -> Option<u64> {
        self.access(IdentityKind::Account, account, true)
    }

    /// A successful proof clears only the matching account's failure budget.
    pub(crate) fn clear_account(&self, account: &str) {
        let Some(key) = key_for(IdentityKind::Account, account) else {
            return;
        };
        let mut store = self.lock_store();
        if let Some(entry) = store.entries.remove(&key) {
            store.expirations.remove(&(entry.expires_at, key));
        }
    }

    fn lock_store(&self) -> MutexGuard<'_, Store> {
        // Operations under the lock have no recoverable panic path; preserve
        // existing budgets if a caller panic nevertheless poisoned the mutex.
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn access(&self, kind: IdentityKind, identity: &str, increment: bool) -> Option<u64> {
        let limit = match kind {
            IdentityKind::Source => self.options.source_limit,
            IdentityKind::Account => self.options.user_failure_limit,
        };
        if limit == 0 || self.ttl_seconds == 0 || self.options.max_entries == 0 {
            return Some(self.default_retry());
        }
        let Some(key) = key_for(kind, identity) else {
            return Some(self.default_retry());
        };
        let mut store = self.lock_store();
        // Production uses Instant, but clamp injected/backward clock values too:
        // rollback must never reset a live fixed window or underflow elapsed time.
        let now = self.clock.seconds().max(store.last_now);
        store.last_now = now;
        let now = u128::from(now);
        prune_expired(&mut store, now);
        // The requested identity may be outside this operation's cleanup batch.
        // Remove it directly so its own TTL takes effect on the first retry.
        if store
            .entries
            .get(&key)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            if let Some(entry) = store.entries.remove(&key) {
                store.expirations.remove(&(entry.expires_at, key));
            }
        }

        if let Some(entry) = store.entries.get_mut(&key) {
            if entry.count >= limit {
                return Some(retry_seconds(entry.expires_at, now));
            }
            if increment {
                entry.count = entry.count.saturating_add(1);
            }
            return None;
        }
        if store.entries.len() >= self.options.max_entries {
            return Some(
                store
                    .expirations
                    .first()
                    .map(|(expires_at, _)| retry_seconds(*expires_at, now))
                    .unwrap_or_else(|| self.default_retry()),
            );
        }
        let expires_at = now + self.ttl_seconds;
        store.entries.insert(
            key,
            Entry {
                count: u32::from(increment),
                expires_at,
            },
        );
        store.expirations.insert((expires_at, key));
        None
    }

    fn default_retry(&self) -> u64 {
        self.ttl_seconds.min(u128::from(u64::MAX)).max(1) as u64
    }
}

fn key_for(kind: IdentityKind, identity: &str) -> Option<Key> {
    if identity.is_empty() || identity.len() > MAX_IDENTITY_BYTES {
        return None;
    }
    Some(Key(kind, Sha256::digest(identity.as_bytes()).into()))
}

fn retry_seconds(expires_at: u128, now: u128) -> u64 {
    expires_at
        .saturating_sub(now)
        .min(u128::from(u64::MAX))
        .max(1) as u64
}

fn prune_expired(store: &mut Store, now: u128) {
    // Reclamation work per operation is fixed, even after a long idle period or
    // a large forward clock jump. Each removal frees both bounded structures.
    for _ in 0..CLEANUP_BATCH {
        let Some(&(expires_at, key)) = store.expirations.first() else {
            break;
        };
        if expires_at > now {
            break;
        }
        store.expirations.pop_first();
        store.entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn seconds(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn fixture(max_entries: usize) -> (LoginLimits, Arc<TestClock>) {
        let clock = Arc::new(TestClock::default());
        let limits = LoginLimits::with_clock(
            LoginLimitOptions {
                max_entries,
                ttl: Duration::from_secs(600),
                source_limit: 3,
                user_failure_limit: 2,
            },
            clock.clone(),
        );
        (limits, clock)
    }

    fn counts(limits: &LoginLimits) -> (usize, usize) {
        let store = limits.lock_store();
        (store.entries.len(), store.expirations.len())
    }

    #[test]
    fn random_username_and_source_flood_stays_inside_shared_hard_capacity() {
        let (limits, _) = fixture(128);
        for number in 0..100_000 {
            let _ = limits.admit_source(&format!("2001:db8::{number:x}"));
            let _ = limits.check_account(&format!("input:random-{number}"));
            let _ = limits.record_failure(&format!("input:random-{number}"));
            assert!(counts(&limits).0 <= 128);
            assert!(counts(&limits).1 <= 128);
        }
        assert_eq!(counts(&limits), (128, 128));
    }

    #[test]
    fn saturation_denies_new_identity_without_resetting_existing_budget() {
        let (limits, _) = fixture(2);
        assert_eq!(limits.check_account("user:victim"), None);
        assert_eq!(limits.record_failure("user:victim"), None);
        assert_eq!(limits.record_failure("user:victim"), None);
        assert_eq!(limits.admit_source("192.0.2.1"), None);
        assert_eq!(limits.check_account("user:attacker"), Some(600));
        assert_eq!(limits.admit_source("192.0.2.2"), Some(600));
        assert_eq!(limits.check_account("user:victim"), Some(600));
        assert_eq!(counts(&limits), (2, 2));
    }

    #[test]
    fn inactive_entries_expire_and_reclaim_both_indexes_in_bounded_batches() {
        let (limits, clock) = fixture(128);
        for number in 0..128 {
            assert_eq!(limits.check_account(&format!("user:{number}")), None);
        }
        clock.0.store(600, Ordering::SeqCst);
        assert_eq!(limits.admit_source("new-source"), None);
        assert_eq!(
            counts(&limits),
            (128 - CLEANUP_BATCH + 1, 128 - CLEANUP_BATCH + 1)
        );
        for _ in 0..4 {
            assert_eq!(limits.check_account("new-account"), None);
        }
        assert_eq!(counts(&limits), (2, 2));
    }

    #[test]
    fn clock_forward_and_rollback_do_not_reset_live_budget_or_panic() {
        let (limits, clock) = fixture(8);
        clock.0.store(100, Ordering::SeqCst);
        for _ in 0..3 {
            assert_eq!(limits.admit_source("source"), None);
        }
        clock.0.store(200, Ordering::SeqCst);
        assert_eq!(limits.admit_source("source"), Some(500));
        clock.0.store(0, Ordering::SeqCst);
        assert_eq!(limits.admit_source("source"), Some(500));
        clock.0.store(699, Ordering::SeqCst);
        assert_eq!(limits.admit_source("source"), Some(1));
        clock.0.store(700, Ordering::SeqCst);
        assert_eq!(limits.admit_source("source"), None);
    }

    #[test]
    fn extreme_forward_clock_never_overflows_or_expires_new_windows_immediately() {
        let (limits, clock) = fixture(8);
        assert_eq!(limits.admit_source("old-source"), None);
        clock.0.store(u64::MAX, Ordering::SeqCst);
        for _ in 0..3 {
            assert_eq!(limits.admit_source("new-source"), None);
        }
        assert_eq!(limits.admit_source("new-source"), Some(600));
        clock.0.store(1, Ordering::SeqCst);
        assert_eq!(limits.admit_source("new-source"), Some(600));
        assert_eq!(counts(&limits), (1, 1));
    }

    #[test]
    fn successful_proof_clears_account_but_keeps_source_admission_budget() {
        let (limits, _) = fixture(8);
        assert_eq!(limits.check_account("identity"), None);
        assert_eq!(limits.record_failure("identity"), None);
        assert_eq!(limits.record_failure("identity"), None);
        for _ in 0..3 {
            assert_eq!(limits.admit_source("identity"), None);
        }
        limits.clear_account("identity");
        assert_eq!(limits.check_account("identity"), None);
        assert_eq!(limits.admit_source("identity"), Some(600));
        assert_eq!(counts(&limits), (2, 2));
    }

    #[test]
    fn concurrent_source_admission_consumes_exactly_one_shared_budget() {
        let (limits, _) = fixture(128);
        let limits = Arc::new(limits);
        let workers: Vec<_> = (0..64)
            .map(|_| {
                let limits = limits.clone();
                std::thread::spawn(move || limits.admit_source("same-source").is_none())
            })
            .collect();
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 3);
        assert_eq!(counts(&limits), (1, 1));
        assert_eq!(limits.clone().admit_source("same-source"), Some(600));
        // Separate process state has a separate budget; restarting resets it.
        // The test deliberately demonstrates that this is not a global quota.
        let (second_replica, _) = fixture(128);
        for _ in 0..3 {
            assert_eq!(second_replica.admit_source("same-source"), None);
        }
        assert_eq!(second_replica.admit_source("same-source"), Some(600));
        drop(second_replica);
        let (restarted_replica, _) = fixture(128);
        assert_eq!(restarted_replica.admit_source("same-source"), None);
    }

    #[test]
    fn zero_budgets_and_oversized_identities_fail_closed_without_allocating_entries() {
        let limits = LoginLimits::new(LoginLimitOptions {
            max_entries: 0,
            ttl: Duration::ZERO,
            source_limit: 0,
            user_failure_limit: 0,
        });
        assert_eq!(limits.admit_source("source"), Some(1));
        assert_eq!(limits.check_account("user"), Some(1));
        assert_eq!(counts(&limits), (0, 0));
        let (limits, _) = fixture(8);
        let oversized = "x".repeat(MAX_IDENTITY_BYTES + 1);
        assert_eq!(limits.admit_source(&oversized), Some(600));
        assert_eq!(limits.check_account(&oversized), Some(600));
        assert_eq!(limits.record_failure(""), Some(600));
        assert_eq!(counts(&limits), (0, 0));
    }
}
