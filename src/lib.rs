//! Independently deployable account authentication and OIDC authority.
//!
//! The canonical platform migration job provisions its schema. This library
//! never migrates, seeds or interprets platform membership authorization.

mod accounts;
mod admin_operations;
mod admission;
mod auth_admin;
#[allow(dead_code)] // The unified protocol consumes this service in Phase 8.
mod auth_consent;
mod auth_invitations;
mod auth_projection;
mod auth_review;
mod authentication;
mod config;
mod client_policy;
mod delivery;
mod error;
mod extractors;
mod internal;
mod login_limits;
mod network;
mod observability;
mod oidc;
mod password;
mod platform_accounts;
mod readiness;
mod sso;
mod state;
#[cfg(test)]
pub(crate) mod test_support;
mod util;

use std::sync::Arc;

/// Load explicit environment, verify the provisioned runtime and serve until a
/// termination signal. Configuration and database errors are reported without
/// connection strings, credential material or request bodies.
pub async fn run_from_env() -> anyhow::Result<()> {
    let config = Arc::new(config::Config::from_env()?);
    let statement = format!("{}ms", config.database_statement_timeout_ms);
    let lock = format!("{}ms", config.database_lock_timeout_ms);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database_pool_max_connections)
        .acquire_timeout(std::time::Duration::from_millis(
            config.database_acquire_timeout_ms,
        ))
        .after_connect(move |connection, _| {
            let statement = statement.clone();
            let lock = lock.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('statement_timeout',$1,false)")
                    .bind(statement)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('lock_timeout',$1,false)")
                    .bind(lock)
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
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .map_err(|_| anyhow::anyhow!("IDENTITY_LISTENER_FAILED"))?;
    let listener = network::BudgetedListener::new(
        listener,
        config.maximum_connections,
        std::time::Duration::from_millis(config.connection_idle_timeout_ms),
    )?;
    tracing::info!(event = "identity_ready", issuer = "https://auth.saas.test");
    let delivery_worker = delivery::start(state);
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<network::Peer>(),
    )
    .with_graceful_shutdown(shutdown())
    .await;
    if let Some(worker) = delivery_worker {
        worker.shutdown().await;
    }
    pool.close().await;
    result.map_err(|_| anyhow::anyhow!("IDENTITY_SERVER_FAILED"))
}

pub(crate) fn router(state: state::AppState) -> axum::Router {
    axum::Router::new()
        .route("/healthz", axum::routing::get(readiness::live))
        .route("/livez", axum::routing::get(readiness::live))
        .route("/readyz", axum::routing::get(readiness::health))
        .route("/health", axum::routing::get(readiness::health))
        .route("/ready", axum::routing::get(readiness::health))
        .route("/health/ready", axum::routing::get(readiness::health))
        .merge(sso::routes())
        .merge(oidc::routes())
        .merge(internal::routes())
        .merge(observability::routes())
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            internal::guard,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admission::bounded,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            observability::observe_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admission::source,
        ))
        .with_state(state)
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
