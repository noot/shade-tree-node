//! Node settings resolved from `SHADENET_*` (or the older `SHADE_TREE_*`) variables, with the
//! same names and defaults as the JavaScript node (`packages/node/gateway/gateway.mjs`,
//! `packages/node/lib/rln.mjs`, `packages/node/lib/root-provider.mjs`,
//! `packages/node/lib/rpc-safety.mjs`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use num_bigint::BigUint;

use crate::chain::{Contract, Kind};
use crate::egress;
use crate::error::Error;
use crate::rpc;
use crate::session;
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
const DEFAULT_LOGS_CHUNK: u64 = 10_000;
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
const MAX_LIMIT: u64 = 65_535;
const DEFAULT_EGRESS_ALLOW: &str = "*:443";

/// Everything an on-chain root source needs (`SHADE_TREE_ADMIT` names `staked` or `paid`).
pub(crate) struct ChainConfig {
    pub(crate) contracts: Vec<Contract>,
    pub(crate) rpc_urls: Vec<String>,
    pub(crate) rpc_timeout: Duration,
    pub(crate) rpc_retries: u64,
    pub(crate) root_freshness: Duration,
    pub(crate) confirmations: u64,
    pub(crate) logs_chunk: u64,
}

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
    members_file: Option<PathBuf>,
    chain: Option<ChainConfig>,
    slash_key: Option<String>,
    slash_contract: Option<String>,
    slash_receiver: Option<String>,
    artifacts: Arc<ArtifactSet>,
    spent_state_file: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    receipts: bool,
    sessions: Option<SessionConfig>,
    egress: egress::Policy,
}

/// Session tickets (`SHADE_TREE_SESSION_TICKETS=1`).
pub(crate) struct SessionConfig {
    pub(crate) max_sessions: usize,
    pub(crate) stream_max: Option<Duration>,
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

        let admit = admission(env_str("ADMIT")?.as_deref(), env_str("ROOTS")?.as_deref())?;
        let members_file = env_str("MEMBERS_FILE")?
            .filter(|raw| !raw.trim().is_empty())
            .map(PathBuf::from);
        if admit.invited && members_file.is_none() {
            return Err(Error::Setting {
                name: "SHADE_TREE_MEMBERS_FILE",
                message: "is required when SHADE_TREE_ADMIT names `invited`: the path of the member set ({\"members\":[leaf,...]})".into(),
            });
        }
        let group_contracts: Vec<String> = env_str("GROUP_CONTRACT")?
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let paid_contract = env_str("PAID_ACCESS_CONTRACT")?
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        if admit.staked && group_contracts.is_empty() {
            return Err(Error::Setting {
                name: "SHADE_TREE_ADMIT",
                message: "names `staked` but SHADE_TREE_GROUP_CONTRACT is not set".into(),
            });
        }
        if admit.paid && paid_contract.is_none() {
            return Err(Error::Setting {
                name: "SHADE_TREE_ADMIT",
                message: "names `paid` but SHADE_TREE_PAID_ACCESS_CONTRACT is not set".into(),
            });
        }
        let provider = env_str("ROOT_PROVIDER")?.unwrap_or_else(|| "node".into());
        if provider.trim() != "node" {
            return Err(Error::Setting {
                name: "SHADE_TREE_ROOT_PROVIDER",
                message: format!(
                    "{:?} is not supported by this build; only `node` is",
                    provider.trim()
                ),
            });
        }
        let mut contracts: Vec<Contract> = Vec::new();
        if admit.staked {
            for address in &group_contracts {
                if !contracts.iter().any(|c| &c.address == address) {
                    contracts.push(Contract {
                        address: address.clone(),
                        kind: Kind::Staked,
                        from_block: 0,
                    });
                }
            }
        }
        if admit.paid {
            if let Some(address) = &paid_contract {
                if !contracts.iter().any(|c| &c.address == address) {
                    contracts.push(Contract {
                        address: address.clone(),
                        kind: Kind::Paid,
                        from_block: 0,
                    });
                }
            }
        }
        for contract in &contracts {
            if !is_address(&contract.address) {
                return Err(Error::Setting {
                    name: "SHADE_TREE_GROUP_CONTRACT",
                    message: format!("{} is not an Ethereum address", contract.address),
                });
            }
        }
        let from_blocks = from_blocks(env_str("FROM_BLOCKS")?.as_deref())?;
        let from_block = env_str("FROM_BLOCK")?
            .as_deref()
            .map(parse_block)
            .transpose()
            .map_err(|message| Error::Setting {
                name: "SHADE_TREE_FROM_BLOCK",
                message,
            })?
            .unwrap_or(0);
        for contract in &mut contracts {
            contract.from_block = from_blocks
                .get(&contract.address)
                .copied()
                .unwrap_or(from_block);
        }
        let chain = if contracts.is_empty() {
            None
        } else {
            let rpc_urls: Vec<String> = env_str("RPC_URL")?
                .unwrap_or_else(|| DEFAULT_RPC_URL.into())
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .take(rpc::MAX_URLS)
                .collect();
            let root_freshness = match env_int("ROOT_FRESHNESS_SECONDS", 0)? {
                0 => epoch_seconds,
                seconds => seconds,
            };
            Some(ChainConfig {
                contracts,
                rpc_urls: if rpc_urls.is_empty() {
                    vec![DEFAULT_RPC_URL.into()]
                } else {
                    rpc_urls
                },
                rpc_timeout: Duration::from_millis(
                    env_int("RPC_TIMEOUT_MS", rpc::DEFAULT_TIMEOUT_MS)?.max(1),
                ),
                rpc_retries: env_int("RPC_RETRIES", rpc::DEFAULT_RETRIES)?.min(rpc::MAX_RETRIES),
                root_freshness: Duration::from_secs(root_freshness),
                confirmations: env_int("CONFIRMATIONS", 0)?,
                logs_chunk: env_int("LOGS_CHUNK", DEFAULT_LOGS_CHUNK)?,
            })
        };
        let artifacts = Arc::new(ArtifactSet::load(
            env_str("ZK_ARTIFACTS")?.as_deref(),
            env_str("ZK_ARTIFACT_LEGACY")?.as_deref(),
        )?);
        let spent_state_file = env_str("SPENT_STATE_FILE")?
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty() && !raw.eq_ignore_ascii_case("off"))
            .map(PathBuf::from);
        let receipts = env_str("RECEIPTS")?.as_deref() == Some("1");
        let sessions = if env_str("SESSION_TICKETS")?.as_deref() == Some("1") {
            Some(SessionConfig {
                max_sessions: count(env_int("SESSION_MAX", session::DEFAULT_MAX_SESSIONS)?)
                    .unwrap_or(usize::MAX),
                stream_max: millis(env_int(
                    "SESSION_STREAM_MAX_MS",
                    session::DEFAULT_STREAM_MAX_MS,
                )?),
            })
        } else {
            None
        };
        let identity_file = if receipts || sessions.is_some() {
            Some(
                env_str("GW_IDENTITY")?
                    .filter(|raw| !raw.trim().is_empty())
                    .map(PathBuf::from)
                    .ok_or_else(|| Error::Setting {
                        name: "SHADE_TREE_GW_IDENTITY",
                        message: if receipts {
                            "is required when SHADE_TREE_RECEIPTS=1".into()
                        } else {
                            "is required when SHADE_TREE_SESSION_TICKETS=1 (a book binds to this node's onion)".into()
                        },
                    })?,
            )
        } else {
            None
        };
        let non_empty = |value: Option<String>| {
            value
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
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
            members_file: if admit.invited { members_file } else { None },
            chain,
            slash_key: non_empty(env_str("SLASH_KEY")?),
            slash_contract: non_empty(env_str("SLASH_CONTRACT")?),
            slash_receiver: non_empty(env_str("SLASH_RECEIVER")?),
            artifacts,
            spent_state_file,
            identity_file,
            receipts,
            sessions,
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

    pub(crate) fn members_file(&self) -> Option<&PathBuf> {
        self.members_file.as_ref()
    }

    pub(crate) fn chain(&self) -> Option<&ChainConfig> {
        self.chain.as_ref()
    }

    pub(crate) fn slash_key(&self) -> Option<&str> {
        self.slash_key.as_deref()
    }

    pub(crate) fn slash_contract(&self) -> Option<&str> {
        self.slash_contract.as_deref()
    }

    pub(crate) fn slash_receiver(&self) -> Option<&str> {
        self.slash_receiver.as_deref()
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

    pub(crate) fn receipts(&self) -> bool {
        self.receipts
    }

    pub(crate) fn sessions(&self) -> Option<&SessionConfig> {
        self.sessions.as_ref()
    }

    pub(crate) fn egress(&self) -> &egress::Policy {
        &self.egress
    }
}

struct Admission {
    invited: bool,
    staked: bool,
    paid: bool,
}

/// `SHADE_TREE_ADMIT=invited[,staked][,paid]` (default `invited`). `SHADE_TREE_ROOTS` is the
/// deprecated alias: `static` is `invited`, `onchain` is `staked,paid`; `ADMIT` wins when both set.
fn admission(admit: Option<&str>, roots: Option<&str>) -> Result<Admission, Error> {
    let spec = match (
        admit.map(str::trim).filter(|s| !s.is_empty()),
        roots.map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(admit), _) => admit.to_string(),
        (None, Some("static")) => "invited".into(),
        (None, Some("onchain")) => "staked,paid".into(),
        (None, Some(other)) => {
            return Err(Error::Setting {
                name: "SHADE_TREE_ROOTS",
                message: format!("{other:?} is not `static` or `onchain`"),
            })
        }
        (None, None) => "invited".into(),
    };
    let mut out = Admission {
        invited: false,
        staked: false,
        paid: false,
    };
    for source in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match source {
            "invited" => out.invited = true,
            "staked" => out.staked = true,
            "paid" => out.paid = true,
            other => {
                return Err(Error::Setting {
                    name: "SHADE_TREE_ADMIT",
                    message: format!("{other:?} is not one of invited, staked, paid"),
                })
            }
        }
    }
    if !(out.invited || out.staked || out.paid) {
        return Err(Error::Setting {
            name: "SHADE_TREE_ADMIT",
            message: "names no admission source".into(),
        });
    }
    Ok(out)
}

fn is_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_block(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .map_err(|_| format!("{raw:?} is not a block number"))
}

/// `SHADE_TREE_FROM_BLOCKS="0xabc=123,0xdef=0x1f"`: a start block per contract.
fn from_blocks(raw: Option<&str>) -> Result<HashMap<String, u64>, Error> {
    let mut out = HashMap::new();
    for item in raw
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some((address, block)) = item.split_once('=') else {
            return Err(Error::Setting {
                name: "SHADE_TREE_FROM_BLOCKS",
                message: format!("{item:?} is not address=block"),
            });
        };
        let block = parse_block(block).map_err(|message| Error::Setting {
            name: "SHADE_TREE_FROM_BLOCKS",
            message,
        })?;
        out.insert(address.trim().to_ascii_lowercase(), block);
    }
    Ok(out)
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

    #[test]
    fn admission_parses_the_policy_and_its_deprecated_alias() {
        let a = admission(None, None).unwrap();
        assert!(a.invited && !a.staked && !a.paid);
        let a = admission(Some("staked, paid"), Some("static")).unwrap();
        assert!(!a.invited && a.staked && a.paid);
        let a = admission(None, Some("onchain")).unwrap();
        assert!(!a.invited && a.staked && a.paid);
        assert!(admission(Some("trusted"), None).is_err());
        assert!(admission(Some(","), None).is_err());
        assert!(admission(None, Some("magic")).is_err());
    }

    #[test]
    fn block_numbers_take_both_forms() {
        assert_eq!(parse_block("0x1f").unwrap(), 31);
        assert_eq!(parse_block(" 31 ").unwrap(), 31);
        assert!(parse_block("x").is_err());
        let map = from_blocks(Some("0xAbC=0x10, 0xdef=2")).unwrap();
        assert_eq!(map["0xabc"], 16);
        assert_eq!(map["0xdef"], 2);
        assert!(from_blocks(Some("nope")).is_err());
    }
}
