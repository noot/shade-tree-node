use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Environment(String),
    #[error("failed to bind {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read the address bound for {addr}")]
    LocalAddr {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to install the {signal} handler")]
    Signal {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{open} connections were still open {grace:?} after shutdown began and were closed")]
    DrainTimeout { open: usize, grace: Duration },
}

impl Error {
    /// Process exit code: 2 for configuration, 1 for a runtime failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Environment(_) => 2,
            Self::Bind { .. }
            | Self::LocalAddr { .. }
            | Self::Signal { .. }
            | Self::DrainTimeout { .. } => 1,
        }
    }
}
