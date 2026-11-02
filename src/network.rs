//! A finite socket budget and idle lifetime, independent from HTTP authority.
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, Sleep},
};

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
pub(crate) fn active_connections() -> usize {
    ACTIVE.load(Ordering::Relaxed)
}
#[derive(Clone, Copy)]
pub(crate) struct Peer(pub(crate) SocketAddr);
pub(crate) struct BudgetedListener {
    inner: TcpListener,
    budget: Arc<Semaphore>,
    idle: Duration,
}
impl BudgetedListener {
    pub(crate) fn new(inner: TcpListener, maximum: usize, idle: Duration) -> io::Result<Self> {
        if maximum == 0 || idle.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid identity connection budget",
            ));
        }
        Ok(Self {
            inner,
            budget: Arc::new(Semaphore::new(maximum)),
            idle,
        })
    }
}
impl Connected<IncomingStream<'_, BudgetedListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, BudgetedListener>) -> Self {
        Self(*stream.remote_addr())
    }
}
pub(crate) struct BudgetedStream {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
}
impl Drop for BudgetedStream {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Listener for BudgetedListener {
    type Io = BudgetedStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = match self.budget.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => std::future::pending().await,
            };
            match self.inner.accept().await {
                Ok((inner, address)) => {
                    ACTIVE.fetch_add(1, Ordering::Relaxed);
                    return (
                        BudgetedStream {
                            inner,
                            _permit: permit,
                            idle: self.idle,
                            deadline: Box::pin(tokio::time::sleep(self.idle)),
                        },
                        address,
                    );
                }
                Err(_) => {
                    drop(permit);
                    tracing::warn!(event = "identity_accept_unavailable");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
impl BudgetedStream {
    fn check_idle(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        use std::future::Future;
        if self.deadline.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "identity connection idle deadline",
            ))
        } else {
            Ok(())
        }
    }
    fn activity(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + self.idle);
    }
}
impl AsyncRead for BudgetedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_idle(cx) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            this.activity();
        }
        result
    }
}
impl AsyncWrite for BudgetedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.check_idle(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        if matches!(result,Poll::Ready(Ok(count)) if count>0) {
            this.activity();
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
