//! The node process: one listener, one task per connection, a bounded drain on shutdown.

use std::sync::Arc;
use std::time::Duration;

use shadenet_proto::{accept_envelope_version, PROTO_MAX, PROTO_MIN};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::envelope::{self, read_envelope, refusal, write_line};
use crate::error::Error;

const REASON_TOO_MANY_CONNECTIONS: &str = "too-many-connections";
const REASON_SESSION_UNSUPPORTED: &str = "session-unsupported";
const REASON_GATEWAY_ERROR: &str = "gateway-error";
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub struct ShadeNode {
    config: Config,
}

struct Shared {
    config: Config,
    connections: Option<Semaphore>,
}

impl ShadeNode {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Serve until SIGTERM or SIGINT, then drain open connections for the configured grace.
    pub async fn run(self) -> Result<(), Error> {
        let addr = self.config.listen();
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| Error::Bind { addr, source })?;
        let bound = listener
            .local_addr()
            .map_err(|source| Error::LocalAddr { addr, source })?;
        let mut shutdown = Shutdown::install()?;
        let shared = Arc::new(Shared {
            connections: self.config.max_connections().map(Semaphore::new),
            config: self.config,
        });
        tracing::info!("gateway up on {bound}");

        let mut connections = JoinSet::new();
        let signal = loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        connections.spawn(serve(Arc::clone(&shared), stream));
                    }
                    Err(e) => {
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                signal = shutdown.recv() => break signal,
            }
        };
        drop(listener);
        tracing::info!(
            "{signal} received; draining {} connections",
            connections.len()
        );
        let grace = shared.config.shutdown_timeout();
        let drained = tokio::time::timeout(grace, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            let open = connections.len();
            connections.abort_all();
            return Err(Error::DrainTimeout { open, grace });
        }
        Ok(())
    }
}

async fn serve(shared: Arc<Shared>, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _permit = match &shared.connections {
        Some(limit) => match limit.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                tracing::debug!(reason = REASON_TOO_MANY_CONNECTIONS, "tunnel rejected");
                write_line(&mut stream, &refusal(REASON_TOO_MANY_CONNECTIONS, &[])).await;
                return;
            }
        },
        None => None,
    };
    let envelope = match read_envelope(&mut stream, shared.config.envelope_timeout()).await {
        Ok((envelope, _early)) => envelope,
        Err(e) => {
            tracing::debug!(reason = e.label(), "tunnel rejected");
            write_line(&mut stream, &refusal(&format!("bad-envelope:{e}"), &[])).await;
            return;
        }
    };
    if let Err(e) = accept_envelope_version(&envelope::version(&envelope), (PROTO_MIN, PROTO_MAX)) {
        let reason = e.to_string();
        tracing::debug!(reason, "tunnel rejected");
        let proto = format!("{{\"min\":{PROTO_MIN},\"max\":{PROTO_MAX}}}");
        write_line(&mut stream, &refusal(&reason, &[("proto", proto)])).await;
        return;
    }
    if envelope.get("session").is_some() || envelope.get("ticket").is_some() {
        tracing::debug!(reason = REASON_SESSION_UNSUPPORTED, "tunnel rejected");
        write_line(&mut stream, &refusal(REASON_SESSION_UNSUPPORTED, &[])).await;
        return;
    }
    if let Err(reason) = shared.config.egress().check_target(envelope.get("target")) {
        tracing::debug!(reason, "tunnel rejected");
        write_line(&mut stream, &refusal(reason, &[])).await;
        return;
    }
    tracing::error!("proof verification is not implemented in this build; refusing the tunnel");
    write_line(&mut stream, &refusal(REASON_GATEWAY_ERROR, &[])).await;
}

struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Shutdown {
    fn install() -> Result<Self, Error> {
        #[cfg(unix)]
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|source| Error::Signal {
            signal: "SIGTERM",
            source,
        })?;
        Ok(Self {
            #[cfg(unix)]
            terminate,
        })
    }

    async fn recv(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "SIGINT",
                _ = self.terminate.recv() => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        }
    }
}
