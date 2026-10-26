//! Node settings resolved from `SHADENET_*` (or the older `SHADE_TREE_*`) variables, with the
//! same names and defaults as the JavaScript node (`packages/node/gateway/gateway.mjs`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::egress;
use crate::error::Error;

const DEFAULT_PORT: u16 = 8443;
const DEFAULT_ENVELOPE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_CONNS: u64 = 1024;
const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_EGRESS_ALLOW: &str = "*:443";

pub struct Config {
    listen: SocketAddr,
    envelope_timeout: Option<Duration>,
    max_connections: Option<usize>,
    shutdown_timeout: Duration,
    egress: egress::Policy,
}

impl Config {
    /// Read every setting from the environment. Unset or unparsable values take their default;
    /// an explicit `0` disables a limit. Port 0 asks the kernel for a free port.
    pub fn from_env() -> Result<Self, Error> {
        let port = env_int("GATEWAY_PORT", u64::from(DEFAULT_PORT))?;
        let port = u16::try_from(port).unwrap_or(DEFAULT_PORT);
        let envelope_timeout = env_int("ENVELOPE_TIMEOUT_MS", DEFAULT_ENVELOPE_TIMEOUT_MS)?;
        let max_connections = env_int("MAX_CONNS", DEFAULT_MAX_CONNS)?;
        let shutdown_timeout = env_int("SHUTDOWN_TIMEOUT_MS", DEFAULT_SHUTDOWN_TIMEOUT_MS)?;
        let allow = env_str("EGRESS_ALLOW")?.unwrap_or_else(|| DEFAULT_EGRESS_ALLOW.to_string());
        let deny = env_str("EGRESS_DENY")?.unwrap_or_default();
        Ok(Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            envelope_timeout: (envelope_timeout > 0)
                .then(|| Duration::from_millis(envelope_timeout)),
            max_connections: (max_connections > 0)
                .then(|| usize::try_from(max_connections).unwrap_or(usize::MAX)),
            shutdown_timeout: Duration::from_millis(shutdown_timeout),
            egress: egress::Policy::parse(&allow, &deny),
        })
    }

    pub(crate) fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn envelope_timeout(&self) -> Option<Duration> {
        self.envelope_timeout
    }

    pub(crate) fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    pub(crate) fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    pub(crate) fn egress(&self) -> &egress::Policy {
        &self.egress
    }
}

fn env_str(name: &str) -> Result<Option<String>, Error> {
    shadenet::env::var(name).map_err(Error::Environment)
}

fn env_int(name: &str, default: u64) -> Result<u64, Error> {
    Ok(env_str(name)?
        .filter(|raw| !raw.is_empty())
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default))
}
