//! Fixed-cardinality operational observations; credentials and protocol material
//! cannot enter labels. This process-local registry never grants authority.

mod http;
mod registry;
mod settings;

pub(crate) use http::{observe_request, routes};
pub(crate) use settings::Settings;

use std::time::Instant;

use crate::error::AppError;

#[derive(Clone, Copy)]
#[allow(clippy::enum_variant_names)] // Keep the existing purpose-qualified timer API across password adapters.
pub(crate) enum Stage {
    PasswordQueue,
    PasswordExecution,
    PasswordResult,
}

impl Stage {
    const ALL: [Self; 3] = [
        Self::PasswordQueue,
        Self::PasswordExecution,
        Self::PasswordResult,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::PasswordQueue => "password_queue",
            Self::PasswordExecution => "password_execution",
            Self::PasswordResult => "password_result",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::PasswordQueue => 0,
            Self::PasswordExecution => 1,
            Self::PasswordResult => 2,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Ok,
    Denied,
    Saturated,
    Timeout,
    Failed,
    Cancelled,
}

impl Outcome {
    const ALL: [Self; 6] = [
        Self::Ok,
        Self::Denied,
        Self::Saturated,
        Self::Timeout,
        Self::Failed,
        Self::Cancelled,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Saturated => "saturated",
            Self::Timeout => "timeout",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::Denied => 1,
            Self::Saturated => 2,
            Self::Timeout => 3,
            Self::Failed => 4,
            Self::Cancelled => 5,
        }
    }
}

pub(crate) struct Timer {
    stage: Stage,
    started: Instant,
    outcome: Outcome,
}

impl Timer {
    pub(crate) fn outcome(&mut self, outcome: Outcome) {
        self.outcome = outcome;
    }

    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.outcome = outcome;
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        registry::stage(self.stage, self.outcome, elapsed.as_secs_f64());
        tracing::debug!(
            event = "identity_password_stage",
            stage = self.stage.label(),
            outcome = self.outcome.label(),
            elapsed_ms = elapsed.as_millis() as u64,
        );
    }
}

/// Count mandatory audit persistence failures without retaining failed content.
pub(crate) fn audit_failure() {
    registry::audit_failure();
}

#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod tests;

pub(crate) fn timer(stage: Stage) -> Timer {
    Timer {
        stage,
        started: Instant::now(),
        outcome: Outcome::Cancelled,
    }
}

pub(crate) fn outcome<T>(result: &Result<T, AppError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Ok,
        Err(AppError::RateLimited(_)) => Outcome::Saturated,
        Err(AppError::Unauthorized(_) | AppError::Forbidden(_) | AppError::BadRequest(_)) => {
            Outcome::Denied
        }
        Err(_) => Outcome::Failed,
    }
}
