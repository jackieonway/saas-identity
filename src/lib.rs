//! Independently deployable account authentication and OIDC authority.
//!
//! The canonical platform migration job provisions its schema. This library
//! never migrates, seeds or interprets platform membership authorization.

mod accounts;
mod admin_operations;
mod authentication;
mod config;
mod error;
mod extractors;
mod internal;
mod login_limits;
mod observability;
mod oidc;
mod password;
mod platform_accounts;
mod readiness;
mod sso;
mod state;
mod util;

use std::sync::Arc;

/// Load explicit environment, verify the provisioned runtime and serve until a
/// termination signal. Configuration and database errors are reported without
/// connection strings, credential material or request bodies.
pub async fn run_from_env() -> anyhow::Result<()> {
    let config = Arc::new(config::Config::from_env()?);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout='3000ms'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET lock_timeout='2000ms'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&config.database_url)
        .await
        .map_err(|_| anyhow::anyhow!("IDENTITY_DATABASE_CONNECTION_FAILED"))?;
    let state = state::IdentityState::new(pool.clone(), config.clone());
    if readiness::verify(&state).await.is_err() {
        pool.close().await;
        anyhow::bail!("IDENTITY_RUNTIME_READINESS_FAILED");
    }
    oidc::initialize(&state)
        .await
        .map_err(|_| anyhow::anyhow!("IDENTITY_ISSUER_READINESS_FAILED"))?;
    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(readiness::health))
        .route("/readyz", axum::routing::get(readiness::health))
        .route("/health", axum::routing::get(readiness::health))
        .route("/ready", axum::routing::get(readiness::health))
        .route("/health/ready", axum::routing::get(readiness::health))
        .merge(sso::routes())
        .merge(oidc::routes())
        .merge(internal::routes())
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            internal::guard,
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .map_err(|_| anyhow::anyhow!("IDENTITY_LISTENER_FAILED"))?;
    tracing::info!(event = "identity_ready", issuer = "https://auth.saas.test");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await;
    pool.close().await;
    result.map_err(|_| anyhow::anyhow!("IDENTITY_SERVER_FAILED"))
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let terminate = async {
            if let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                signal.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
