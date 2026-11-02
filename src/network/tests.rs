use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "this host's native loopback TCP is unavailable; execute actual socket test on WSL Linux"
)]
async fn socket_capacity_is_held_until_drop_and_idle_connections_expire() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut listener = BudgetedListener::new(listener, 1, Duration::from_millis(250))?;
    let mut first = TcpStream::connect(address).await?;
    let (mut accepted, _) = listener.accept().await;
    let second = TcpStream::connect(address).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "a second socket bypassed the active connection budget"
    );
    first.write_all(b"x").await?;
    let mut buffer = [0u8; 1];
    accepted.read_exact(&mut buffer).await?;
    assert_eq!(buffer, [b'x']);
    let result =
        tokio::time::timeout(Duration::from_secs(2), accepted.read_exact(&mut buffer)).await?;
    assert!(matches!(result,Err(error) if error.kind()==io::ErrorKind::TimedOut));
    drop(accepted);
    drop(first);
    let (accepted_again, _) =
        tokio::time::timeout(Duration::from_secs(2), listener.accept()).await?;
    drop(accepted_again);
    drop(second);
    Ok(())
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "this host's native loopback TCP is unavailable; execute actual socket test on WSL Linux"
)]
async fn slow_http_body_times_out_before_authority_and_releases_admission() -> anyhow::Result<()> {
    use axum::{middleware, routing::post, Router};
    use std::{collections::HashMap, sync::atomic::AtomicUsize};
    let config = Arc::new(crate::config::Config::from_values(&HashMap::from([
        ("APP_ENV".into(), "test".into()),
        (
            "DATABASE_URL".into(),
            "postgres://owned@127.0.0.1:9/owned_phase22".into(),
        ),
        ("AUTH_BODY_TIMEOUT_MS".into(), "100".into()),
        ("AUTH_REQUEST_CONCURRENCY".into(), "1".into()),
    ]))?);
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy(&config.database_url)?;
    let state = crate::state::AppState::new(pool, config);
    let hits = Arc::new(AtomicUsize::new(0));
    let authority_hits = hits.clone();
    let app = Router::new()
        .route(
            "/oauth/probe",
            post(move || {
                let authority_hits = authority_hits.clone();
                async move {
                    authority_hits.fetch_add(1, Ordering::SeqCst);
                    "accepted"
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::admission::bounded,
        ))
        .layer(middleware::from_fn_with_state(
            state,
            crate::admission::source,
        ));
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp.local_addr()?;
    let listener = BudgetedListener::new(tcp, 2, Duration::from_secs(2))?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    let result = async {
        let mut slow = TcpStream::connect(address).await?;
        slow.write_all(b"POST /oauth/probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nx").await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), slow.read_to_end(&mut response)).await??;
        let mut response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 408"));
        assert!(response.to_ascii_lowercase().contains("cache-control: no-store"));
        assert!(response.contains("invalid_request"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let mut valid = TcpStream::connect(address).await?;
        valid.write_all(b"POST /oauth/probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        response.clear();
        tokio::time::timeout(Duration::from_secs(2), valid.read_to_string(&mut response)).await??;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        anyhow::Ok(())
    }.await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(3), server).await???;
    result
}
