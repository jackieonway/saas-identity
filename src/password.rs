use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

use crate::error::AppError;

/// Bound password input before admission or any owned copy is made.
pub(crate) const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_PASSWORD_HASH_BYTES: usize = 1024;

/// Process-local, bounded Argon2 execution shared by all HTTP password paths.
///
/// Admission is fail-closed once the running and waiting capacities are full.
/// Queue and execution deadlines return 429 with a one-second retry hint. A
/// response deadline or cancelled caller cannot stop Argon2: the blocking job
/// retains both permits until it actually exits, including time spent waiting
/// for Tokio's blocking thread pool. No password policy or Argon2 cost is reduced.
#[derive(Clone)]
pub(crate) struct PasswordService {
    admitted: Arc<Semaphore>,
    running: Arc<Semaphore>,
    capacity: usize,
    concurrency: usize,
    queue_timeout: Duration,
    execution_timeout: Duration,
    #[cfg(test)]
    test_budget: TestBudget,
}

#[cfg(test)]
#[derive(Clone)]
struct TestBudget {
    capacity: usize,
    concurrency: usize,
    active: Arc<std::sync::atomic::AtomicUsize>,
    changed: Arc<tokio::sync::Notify>,
}

/// Read-only test instrumentation; absent from production builds.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PasswordServiceStats {
    pub(crate) active: usize,
    pub(crate) queued: usize,
    pub(crate) admitted: usize,
}

#[cfg(test)]
struct ActiveTestJob(TestBudget);

#[cfg(test)]
impl Drop for ActiveTestJob {
    fn drop(&mut self) {
        self.0
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

impl PasswordService {
    /// Construct one process-wide password budget.
    ///
    /// `queue_capacity` excludes the running capacity and may be zero. The
    /// deployment must divide its total budget among replicas; these permits
    /// are deliberately not advertised as a cross-process quota.
    ///
    /// # Panics
    ///
    /// Panics if concurrency is zero or the total capacity exceeds Tokio's
    /// semaphore limit. Configuration validation must reject those values.
    pub(crate) fn new(
        concurrency: usize,
        queue_capacity: usize,
        queue_timeout: Duration,
        execution_timeout: Duration,
    ) -> Self {
        assert!(concurrency > 0, "password concurrency must be positive");
        let capacity = concurrency
            .checked_add(queue_capacity)
            .filter(|capacity| *capacity <= Semaphore::MAX_PERMITS)
            .expect("validated password admission capacity");
        Self {
            admitted: Arc::new(Semaphore::new(capacity)),
            running: Arc::new(Semaphore::new(concurrency)),
            capacity,
            concurrency,
            queue_timeout,
            execution_timeout,
            #[cfg(test)]
            test_budget: TestBudget {
                capacity,
                concurrency,
                active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                changed: Arc::new(tokio::sync::Notify::new()),
            },
        }
    }

    /// Reserved execution permits include work waiting for Tokio's blocking
    /// executor. Timed-out callers retain their permits until that work exits.
    pub(crate) fn operational_counts(&self) -> (usize, usize) {
        let admitted = self
            .capacity
            .saturating_sub(self.admitted.available_permits());
        let running = self
            .concurrency
            .saturating_sub(self.running.available_permits());
        (running, admitted.saturating_sub(running))
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> PasswordServiceStats {
        let admitted = self.test_budget.capacity - self.admitted.available_permits();
        let reserved = self.test_budget.concurrency - self.running.available_permits();
        PasswordServiceStats {
            active: self
                .test_budget
                .active
                .load(std::sync::atomic::Ordering::SeqCst),
            queued: admitted.saturating_sub(reserved),
            admitted,
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_active(&self) -> PasswordServiceStats {
        loop {
            let notified = self.test_budget.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let snapshot = self.snapshot();
            if snapshot.active > 0 {
                return snapshot;
            }
            notified.await;
        }
    }

    /// Hash an accepted password on a bounded blocking worker.
    ///
    /// Input over 1024 bytes returns 400; overload or either deadline returns
    /// 429. Strength validation remains a separate write-policy decision.
    pub(crate) async fn hash(&self, password: &str) -> Result<String, AppError> {
        validate_input_length(password)?;
        self.run(|| {
            let password = password.to_owned();
            move || hash_password(&password).map_err(AppError::from)
        })
        .await
    }

    /// Verify a password on a bounded blocking worker, preserving Argon2 PHC
    /// compatibility. Invalid stored hashes return false; oversized password
    /// input returns 400, and exhausted capacity or deadlines return 429.
    pub(crate) async fn verify(&self, hash: &str, password: &str) -> Result<bool, AppError> {
        validate_input_length(password)?;
        // PHC strings generated by the existing/default Argon2 policy are far
        // below this limit. Corrupt database values must not amplify copies.
        if hash.len() > MAX_PASSWORD_HASH_BYTES {
            return Ok(false);
        }
        self.run(|| {
            let hash = hash.to_owned();
            let password = password.to_owned();
            move || Ok(verify_password(&hash, &password))
        })
        .await
    }

    async fn run<T, F, Prepare>(&self, prepare: Prepare) -> Result<T, AppError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, AppError> + Send + 'static,
        Prepare: FnOnce() -> F + Send,
    {
        let mut queued = crate::observability::timer(crate::observability::Stage::PasswordQueue);
        let admitted = self.admitted.clone().try_acquire_owned().map_err(|_| {
            tracing::warn!(event = "password_admission_full");
            queued.outcome(crate::observability::Outcome::Saturated);
            AppError::RateLimited(1)
        })?;
        let running =
            tokio::time::timeout(self.queue_timeout, self.running.clone().acquire_owned())
                .await
                .map_err(|_| {
                    tracing::warn!(event = "password_queue_timeout");
                    queued.outcome(crate::observability::Outcome::Timeout);
                    AppError::RateLimited(1)
                })?
                .map_err(|_| AppError::Server(anyhow::anyhow!("password worker budget closed")))?;

        // Do not copy secrets while queued. There is no await between taking
        // the running permit and transferring both permits into the worker.
        queued.finish(crate::observability::Outcome::Ok);
        let work = prepare();
        #[cfg(test)]
        let test_budget = self.test_budget.clone();
        let job = tokio::task::spawn_blocking(move || {
            let execution =
                crate::observability::timer(crate::observability::Stage::PasswordExecution);
            let _admitted = admitted;
            let _running = running;
            #[cfg(test)]
            let _active = {
                test_budget
                    .active
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                test_budget.changed.notify_waiters();
                ActiveTestJob(test_budget)
            };
            let result = work();
            execution.finish(crate::observability::outcome(&result));
            result
        });
        let mut response = crate::observability::timer(crate::observability::Stage::PasswordResult);
        let joined = tokio::time::timeout(self.execution_timeout, job)
            .await
            .map_err(|_| {
                tracing::warn!(event = "password_execution_timeout");
                response.outcome(crate::observability::Outcome::Timeout);
                AppError::RateLimited(1)
            })?
            .map_err(|_| AppError::Server(anyhow::anyhow!("password worker failed")));
        let result = match joined {
            Ok(result) => result,
            Err(error) => {
                response.finish(crate::observability::Outcome::Failed);
                return Err(error);
            }
        };
        response.finish(crate::observability::outcome(&result));
        result
    }
}

fn validate_input_length(password: &str) -> Result<(), AppError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::bad_request("密码不能超过 1024 字节"));
    }
    Ok(())
}

/// Every production password write uses the same minimum account policy.
/// Development keeps the original six-byte compatibility rule.
pub(crate) fn validate_for_config(
    password: &str,
    config: &crate::config::Config,
) -> Result<(), crate::error::AppError> {
    if config.is_production() {
        if password.chars().count() < 12
            || password.len() > 1024
            || password.trim().is_empty()
            || password.chars().any(char::is_control)
            || [
                "admin123", "Zs@12345", "Ls@12345", "Ww@12345", "Tq@12345", "Cj@12345",
            ]
            .contains(&password)
        {
            return Err(crate::error::AppError::bad_request(
                "生产密码至少 12 个字符，不能使用演示密码、控制字符或空白值",
            ));
        }
    } else if password.len() < 6 {
        return Err(crate::error::AppError::bad_request("密码长度不能少于 6 位"));
    }
    Ok(())
}

/// Synchronous Argon2 helper for offline setup and tests only. HTTP paths must
/// use the shared [`PasswordService`] so CPU and waiting memory remain bounded.
pub(crate) fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("密码哈希计算失败: {e}"))?;
    Ok(hash.to_string())
}

/// Synchronous Argon2 verification for startup/tests (invalid PHC returns false).
/// HTTP paths must use [`PasswordService::verify`].
pub(crate) fn verify_password(hash: &str, password: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Condvar, Mutex,
        },
        task::Poll,
    };
    use tokio::sync::oneshot;

    struct Release(Arc<(Mutex<bool>, Condvar)>);

    impl Release {
        fn open(&self) {
            let (open, changed) = &*self.0;
            *open.lock().unwrap() = true;
            changed.notify_all();
        }
    }

    impl Drop for Release {
        fn drop(&mut self) {
            self.open();
        }
    }

    // The release guard prevents an assertion failure from leaving a blocking
    // worker stuck while the Tokio test runtime is shutting down.
    fn blocked_work() -> (
        impl FnOnce() -> Result<(), AppError> + Send + 'static,
        oneshot::Receiver<()>,
        Release,
    ) {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Release(gate.clone());
        let (started, observed_start) = oneshot::channel();
        (
            move || {
                started.send(()).unwrap();
                let (open, changed) = &*gate;
                let mut open = open.lock().unwrap();
                while !*open {
                    open = changed.wait(open).unwrap();
                }
                Ok(())
            },
            observed_start,
            release,
        )
    }

    async fn assert_pending<T>(future: Pin<&mut impl Future<Output = T>>) {
        let mut future = future;
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    fn service(concurrency: usize, queued: usize) -> PasswordService {
        PasswordService::new(
            concurrency,
            queued,
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
    }

    #[tokio::test]
    async fn admission_bounds_running_and_waiting_jobs_before_copying_inputs() {
        let service = service(2, 2);
        let mut active_jobs = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let (work, started, release) = blocked_work();
            let worker = service.clone();
            active_jobs.push(tokio::spawn(async move { worker.run(|| work).await }));
            started.await.unwrap();
            releases.push(release);
        }
        assert_eq!(service.running.available_permits(), 0);
        let active = service.wait_for_active().await;
        assert_eq!((active.active, active.queued, active.admitted), (2, 0, 2));

        let prepared = Arc::new(AtomicUsize::new(0));
        let make_work = || {
            prepared.fetch_add(1, Ordering::SeqCst);
            || Ok(())
        };
        let mut queued_a = Box::pin(service.run(make_work));
        let mut queued_b = Box::pin(service.run(make_work));
        assert_pending(queued_a.as_mut()).await;
        assert_pending(queued_b.as_mut()).await;
        assert_eq!(service.admitted.available_permits(), 0);
        let full = service.snapshot();
        assert_eq!((full.active, full.queued, full.admitted), (2, 2, 4));
        assert_eq!(prepared.load(Ordering::SeqCst), 0);
        assert!(matches!(
            service.run(make_work).await,
            Err(AppError::RateLimited(1))
        ));
        assert_eq!(prepared.load(Ordering::SeqCst), 0);

        // Cancellation while queued releases only its own admission slot.
        drop(queued_a);
        assert_eq!(service.admitted.available_permits(), 1);
        assert_eq!(service.running.available_permits(), 0);
        for release in releases {
            release.open();
        }
        for job in active_jobs {
            job.await.unwrap().unwrap();
        }
        queued_b.await.unwrap();
        assert_eq!(prepared.load(Ordering::SeqCst), 1);
        assert_eq!(service.admitted.available_permits(), 4);
        assert_eq!(service.running.available_permits(), 2);
        let idle = service.snapshot();
        assert_eq!((idle.active, idle.queued, idle.admitted), (0, 0, 0));
    }

    #[tokio::test]
    async fn cancelling_a_running_request_keeps_both_permits_until_work_exits() {
        let service = service(1, 0);
        let (work, started, release) = blocked_work();
        let worker = service.clone();
        let caller = tokio::spawn(async move { worker.run(|| work).await });
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(service.admitted.available_permits(), 0);
        assert_eq!(service.running.available_permits(), 0);
        assert!(matches!(
            service.run(|| || Ok(())).await,
            Err(AppError::RateLimited(1))
        ));

        release.open();
        let permit = tokio::time::timeout(Duration::from_secs(2), service.admitted.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        service.run(|| || Ok(())).await.unwrap();
        assert_eq!(service.running.available_permits(), 1);
    }

    #[tokio::test]
    async fn execution_timeout_keeps_both_permits_until_work_exits() {
        let service = PasswordService::new(1, 0, Duration::from_secs(5), Duration::from_millis(25));
        let (work, started, release) = blocked_work();
        let worker = service.clone();
        let caller = tokio::spawn(async move { worker.run(|| work).await });
        started.await.unwrap();
        assert!(matches!(
            caller.await.unwrap(),
            Err(AppError::RateLimited(1))
        ));
        assert_eq!(service.admitted.available_permits(), 0);
        assert_eq!(service.running.available_permits(), 0);
        assert!(matches!(
            service.run(|| || Ok(())).await,
            Err(AppError::RateLimited(1))
        ));

        release.open();
        let permit = tokio::time::timeout(Duration::from_secs(2), service.admitted.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(service.running.available_permits(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_deadline_does_not_block_the_tokio_worker_or_leak_admission() {
        let service = PasswordService::new(1, 1, Duration::ZERO, Duration::from_secs(10));
        let (work, started, release) = blocked_work();
        let worker = service.clone();
        let caller = tokio::spawn(async move { worker.run(|| work).await });
        started.await.unwrap();

        let probe = tokio::spawn(async {
            tokio::task::yield_now().await;
            "healthy"
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), probe)
                .await
                .unwrap()
                .unwrap(),
            "healthy"
        );
        let copied = AtomicUsize::new(0);
        assert!(matches!(
            service
                .run(|| {
                    copied.fetch_add(1, Ordering::SeqCst);
                    || Ok(())
                })
                .await,
            Err(AppError::RateLimited(1))
        ));
        assert_eq!(copied.load(Ordering::SeqCst), 0);
        assert_eq!(service.admitted.available_permits(), 1);
        release.open();
        caller.await.unwrap().unwrap();
        assert_eq!(service.admitted.available_permits(), 2);
    }

    #[tokio::test]
    async fn asynchronous_argon2_preserves_legacy_hash_and_default_cost() {
        let service = service(1, 1);
        let password = "Synthetic-compatible-password";
        let hash = service.hash(password).await.unwrap();
        let parsed = PasswordHash::new(&hash).unwrap();
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert_eq!(parsed.version, Some(19));
        for (name, expected) in [("m", 19456), ("t", 2), ("p", 1)] {
            assert_eq!(parsed.params.get_decimal(name), Some(expected));
        }
        assert!(service.verify(&hash, password).await.unwrap());
        assert!(!service.verify(&hash, "wrong-password").await.unwrap());
        let legacy = hash_password(password).unwrap();
        assert!(service.verify(&legacy, password).await.unwrap());
        assert!(!service.verify("invalid-PHC", password).await.unwrap());
    }

    #[tokio::test]
    async fn oversized_password_is_rejected_before_admission_with_utf8_byte_boundary() {
        let service = service(1, 0);
        let admission = service.admitted.clone().try_acquire_owned().unwrap();
        let oversized = "密".repeat(342);
        assert_eq!(oversized.len(), 1026);
        assert!(matches!(
            service.hash(&oversized).await,
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            service.verify("invalid-PHC", &oversized).await,
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            service.hash(&"x".repeat(1024)).await,
            Err(AppError::RateLimited(1))
        ));
        drop(admission);
    }

    #[tokio::test]
    async fn overload_preserves_http_429_and_retry_after_contract() {
        use axum::{http::StatusCode, response::IntoResponse};

        let service = service(1, 0);
        let _admission = service.admitted.clone().try_acquire_owned().unwrap();
        let response = service
            .hash("Synthetic-password")
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "1");
    }

    #[test]
    fn production_writes_reject_demo_and_short_passwords_with_development_compatibility() {
        let mut config = crate::config::Config::from_values(&std::collections::HashMap::from([(
            "DATABASE_URL".into(),
            "postgresql://identity_runtime@localhost/identity_task".into(),
        )]))
        .unwrap();
        assert!(validate_for_config("admin123", &config).is_ok());
        assert!(validate_for_config("123456", &config).is_ok());
        assert!(validate_for_config("short", &config).is_err());
        config.app_env = "production".into();
        for candidate in [
            "admin123",
            "Zs@12345",
            "Ls@12345",
            "Ww@12345",
            "Tq@12345",
            "Cj@12345",
            "12345678901",
            "            ",
            "long-password\n-invalid",
        ] {
            assert!(validate_for_config(candidate, &config).is_err());
        }
        assert!(validate_for_config(&"x".repeat(1025), &config).is_err());
        assert!(validate_for_config("Synthetic-new-user-password", &config).is_ok());
    }
}
