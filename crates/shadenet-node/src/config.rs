//! Node settings resolved from `SHADENET_*` (or the older `SHADE_TREE_*`) variables, with the
//! same names and defaults as the JavaScript node (`packages/node/gateway/gateway.mjs`,
//! `packages/node/lib/rln.mjs`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use num_bigint::BigUint;

use crate::egress;
use crate::error::Error;
use crate::verify::ArtifactSet;

const DEFAULT_PORT: u16 = 8443;
const DEFAULT_ENVELOPE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_DNS_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_CONNS: u64 = 1024;
const DEFAULT_MAX_CONNS_PER_NULLIFIER: u64 = 8;
const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_REPLAY_WINDOW_MS: u64 = 5_000;
const DEFAULT_EPOCH_SECONDS: u64 = 120;
const DEFAULT_SLOTS: u64 = 8;
const MAX_LIMIT: u64 = 65_535;
const DEFAULT_EGRESS_ALLOW: &str = "*:443";

pub struct Config {
    listen: SocketAddr,
    envelope_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    dns_timeout: Option<Duration>,
    max_connections: Option<usize>,
    max_connections_per_nullifier: Option<usize>,
    shutdown_timeout: Duration,
    replay_window: Duration,
    epoch_seconds: u64,
    rln_identifier: BigUint,
    slots: u64,
    tiers: Vec<u64>,
    max_payload_bytes: u64,
    allow_private_targets: bool,
    members_file: PathBuf,
    artifacts: Arc<ArtifactSet>,
    spent_state_file: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    egress: egress::Policy,
}

impl Config {
    /// Read every setting from the environment. Unset or unparsable numeric values take their
    /// default; an explicit `0` disables a limit. Port 0 asks the kernel for a free port.
    pub fn from_env() -> Result<Self, Error> {
        let port = env_int("GATEWAY_PORT", u64::from(DEFAULT_PORT))?;
        let port = u16::try_from(port).unwrap_or(DEFAULT_PORT);
        let envelope_timeout = env_int("ENVELOPE_TIMEOUT_MS", DEFAULT_ENVELOPE_TIMEOUT_MS)?;
        let idle_timeout = env_int("TUNNEL_IDLE_TIMEOUT_MS", DEFAULT_IDLE_TIMEOUT_MS)?;
        let dns_timeout = env_int("DNS_TIMEOUT_MS", DEFAULT_DNS_TIMEOUT_MS)?;
        let max_connections = env_int("MAX_CONNS", DEFAULT_MAX_CONNS)?;
        let per_nullifier = env_int("MAX_CONNS_PER_NULLIFIER", DEFAULT_MAX_CONNS_PER_NULLIFIER)?;
        let shutdown_timeout = env_int("SHUTDOWN_TIMEOUT_MS", DEFAULT_SHUTDOWN_TIMEOUT_MS)?;
        let replay_window = env_int("REPLAY_WINDOW_MS", DEFAULT_REPLAY_WINDOW_MS)?;
        let replay_window = if replay_window == 0 {
            DEFAULT_REPLAY_WINDOW_MS
        } else {
            replay_window
        };
        let epoch_seconds = env_int("EPOCH_SECONDS", DEFAULT_EPOCH_SECONDS)?.max(1);
        let rln_identifier = env_str("RLN_IDENTIFIER")?
            .filter(|raw| !raw.trim().is_empty())
            .map(|raw| {
                BigUint::parse_bytes(raw.trim().as_bytes(), 10).ok_or_else(|| Error::Setting {
                    name: "SHADE_TREE_RLN_IDENTIFIER",
                    message: "must be a decimal integer".into(),
                })
            })
            .transpose()?
            .unwrap_or_else(|| BigUint::from(1_u8));
        let slots = limit(
            "SHADE_TREE_SLOTS",
            env_str("SLOTS")?.as_deref(),
            DEFAULT_SLOTS,
        )?;
        let tiers = tiers(env_str("TIERS")?.as_deref(), slots)?;
        let max_payload_bytes = env_int(
            "TUNNEL_MAX_PAYLOAD_BYTES",
            shadenet_proto::DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES,
        )?;
        let allow = env_str("EGRESS_ALLOW")?.unwrap_or_else(|| DEFAULT_EGRESS_ALLOW.to_string());
        let deny = env_str("EGRESS_DENY")?.unwrap_or_default();
        let admit = env_str("ADMIT")?.unwrap_or_else(|| "invited".into());
        for source in admit.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if source != "invited" {
                return Err(Error::Setting {
                    name: "SHADE_TREE_ADMIT",
                    message: format!("{source:?} is not supported by this build; only `invited` (a members file) is"),
                });
            }
        }
        let members_file = env_str("MEMBERS_FILE")?
            .filter(|raw| !raw.trim().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| Error::Setting {
                name: "SHADE_TREE_MEMBERS_FILE",
                message:
                    "is required: the path of the invited member set ({\"members\":[leaf,...]})"
                        .into(),
            })?;
        let artifacts = Arc::new(ArtifactSet::load(
            env_str("ZK_ARTIFACTS")?.as_deref(),
            env_str("ZK_ARTIFACT_LEGACY")?.as_deref(),
        )?);
        let spent_state_file = env_str("SPENT_STATE_FILE")?
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty() && !raw.eq_ignore_ascii_case("off"))
            .map(PathBuf::from);
        let identity_file = if env_str("RECEIPTS")?.as_deref() == Some("1") {
            Some(
                env_str("GW_IDENTITY")?
                    .filter(|raw| !raw.trim().is_empty())
                    .map(PathBuf::from)
                    .ok_or_else(|| Error::Setting {
                        name: "SHADE_TREE_GW_IDENTITY",
                        message: "is required when SHADE_TREE_RECEIPTS=1".into(),
                    })?,
            )
        } else {
            None
        };
        Ok(Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            envelope_timeout: millis(envelope_timeout),
            idle_timeout: millis(idle_timeout),
            dns_timeout: millis(dns_timeout),
            max_connections: count(max_connections),
            max_connections_per_nullifier: count(per_nullifier),
            shutdown_timeout: Duration::from_millis(shutdown_timeout),
            replay_window: Duration::from_millis(replay_window),
            epoch_seconds,
            rln_identifier,
            slots,
            tiers,
            max_payload_bytes,
            allow_private_targets: env_str("ALLOW_PRIVATE_TARGETS")?.as_deref() == Some("1"),
            members_file,
            artifacts,
            spent_state_file,
            identity_file,
            egress: egress::Policy::parse(&allow, &deny),
        })
    }

    pub(crate) fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn envelope_timeout(&self) -> Option<Duration> {
        self.envelope_timeout
    }

    pub(crate) fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    pub(crate) fn dns_timeout(&self) -> Option<Duration> {
        self.dns_timeout
    }

    pub(crate) fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    pub(crate) fn max_connections_per_nullifier(&self) -> Option<usize> {
        self.max_connections_per_nullifier
    }

    pub(crate) fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    pub(crate) fn replay_window(&self) -> Duration {
        self.replay_window
    }

    pub(crate) fn epoch_seconds(&self) -> u64 {
        self.epoch_seconds
    }

    pub(crate) fn rln_identifier(&self) -> &BigUint {
        &self.rln_identifier
    }

    pub(crate) fn slots(&self) -> u64 {
        self.slots
    }

    pub(crate) fn tiers(&self) -> &[u64] {
        &self.tiers
    }

    pub(crate) fn max_payload_bytes(&self) -> u64 {
        self.max_payload_bytes
    }

    pub(crate) fn allow_private_targets(&self) -> bool {
        self.allow_private_targets
    }

    pub(crate) fn members_file(&self) -> &PathBuf {
        &self.members_file
    }

    pub(crate) fn artifacts(&self) -> Arc<ArtifactSet> {
        Arc::clone(&self.artifacts)
    }

    pub(crate) fn spent_state_file(&self) -> Option<&PathBuf> {
        self.spent_state_file.as_ref()
    }

    pub(crate) fn identity_file(&self) -> Option<&PathBuf> {
        self.identity_file.as_ref()
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

fn millis(value: u64) -> Option<Duration> {
    (value > 0).then(|| Duration::from_millis(value))
}

fn count(value: u64) -> Option<usize> {
    (value > 0).then(|| usize::try_from(value).unwrap_or(usize::MAX))
}

/// A tier limit: an integer in `1..=65535` (the circuit range-checks with 16 bits).
fn limit(name: &'static str, raw: Option<&str>, default: u64) -> Result<u64, Error> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(default);
    };
    let bad = |message: String| Error::Setting { name, message };
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!(
            "bad tier {:?} (integers only)",
            raw.chars().take(16).collect::<String>()
        )));
    }
    let value: u64 = raw
        .parse()
        .map_err(|_| bad(format!("tier out of range 1..{MAX_LIMIT}")))?;
    if !(1..=MAX_LIMIT).contains(&value) {
        return Err(bad(format!(
            "tier out of range 1..{MAX_LIMIT} (got {value})"
        )));
    }
    Ok(value)
}

/// `SHADE_TREE_TIERS="8,32"`: the distinct limits a slash may name, always including the
/// default tier, ascending.
fn tiers(raw: Option<&str>, slots: u64) -> Result<Vec<u64>, Error> {
    let mut out = vec![slots];
    for part in raw.unwrap_or("").split(',') {
        if part.trim().is_empty() {
            continue;
        }
        out.push(limit("SHADE_TREE_TIERS", Some(part), slots)?);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_always_include_the_default_and_are_sorted_and_distinct() {
        assert_eq!(tiers(None, 8).unwrap(), vec![8]);
        assert_eq!(tiers(Some("32, 8,,1"), 8).unwrap(), vec![1, 8, 32]);
        assert!(tiers(Some("x"), 8).is_err());
        assert!(tiers(Some("0"), 8).is_err());
        assert!(tiers(Some("65536"), 8).is_err());
    }
}
