#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => tracing_subscriber::EnvFilter::try_new(value)
            .map_err(|_| anyhow::anyhow!("IDENTITY_LOG_FILTER_INVALID"))?,
        Ok(_) | Err(std::env::VarError::NotPresent) => tracing_subscriber::EnvFilter::new("info"),
        Err(_) => anyhow::bail!("IDENTITY_LOG_FILTER_INVALID"),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    if !required_warn_logging_enabled() {
        anyhow::bail!("IDENTITY_REQUIRED_WARN_LOGGING_DISABLED");
    }
    saas_identity::run_from_env().await
}

fn required_warn_logging_enabled() -> bool {
    tracing::enabled!(target:"saas_identity::delivery",tracing::Level::WARN)
        && tracing::enabled!(target:"saas_identity::delivery::worker",tracing::Level::WARN)
        && tracing::enabled!(target:"saas_identity::password",tracing::Level::WARN)
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::prelude::*;

    #[test]
    fn delivery_tick_and_worker_and_password_warnings_are_all_required() {
        for (filter, accepted) in [
            ("info", true),
            ("error", false),
            (
                "error,saas_identity::delivery::worker=warn,saas_identity::password=warn",
                false,
            ),
            (
                "error,saas_identity::delivery=warn,saas_identity::password=warn",
                true,
            ),
            ("info,saas_identity::delivery=error", false),
        ] {
            let subscriber =
                tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new(filter));
            tracing::subscriber::with_default(subscriber, || {
                assert_eq!(super::required_warn_logging_enabled(), accepted);
            });
        }
    }
}
