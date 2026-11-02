//! A bounded outbox consumer; authority mutations only enqueue durable facts.
mod transport;
mod worker;

pub(crate) use transport::Settings;

pub(crate) struct Worker {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}
pub(crate) fn start(state: crate::state::AppState) -> Option<Worker> {
    if !state.config.delivery.worker_enabled {
        return None;
    }
    let (stop, mut signal) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result=signal.changed()=>{ if result.is_err() || *signal.borrow() { break; } },
                _=tokio::time::sleep(std::time::Duration::from_secs(1))=>{
                    if worker::tick(&state).await.is_err() {
                        tracing::warn!(event="identity_delivery_tick_unavailable");
                    }
                }
            }
        }
    });
    Some(Worker { stop, task })
}
impl Worker {
    pub(crate) async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = self.task.await;
        }
    }
}
