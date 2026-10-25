use std::time::Instant;

use crate::error::AppError;

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    PasswordQueue,
    PasswordExecution,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::PasswordQueue => "password_queue",
            Self::PasswordExecution => "password_execution",
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
        tracing::debug!(
            event = "identity_password_stage",
            stage = self.stage.label(),
            outcome = self.outcome.label(),
            elapsed_ms = self.started.elapsed().as_millis() as u64,
        );
    }
}

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
