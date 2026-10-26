//! The node process: one listener, one task per connection, a bounded drain on shutdown.
//! Per connection, the order is the JavaScript node's: connection cap, envelope framing,
//! version gate, target policy, proof verification, spent set, per-nullifier cap, payload
//! allowance, DNS, dial, acknowledgement, relay.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shadenet_proto::{accept_envelope_version, PROTO_MAX, PROTO_MIN};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::egress;
use crate::envelope::{self, read_envelope, refusal, refuse, write_line};
use crate::error::Error;
use crate::receipt;
use crate::roots::MemberSet;
use crate::slash;
use crate::spent::{Admission, Share, SpentSet};
use crate::tunnel::{self, Budget};
use crate::verify::{Refusal, Verifier};

const REASON_TOO_MANY_CONNECTIONS: &str = "too-many-connections";
const REASON_SESSION_UNSUPPORTED: &str = "session-unsupported";
const REASON_NULLIFIER_CONN_LIMIT: &str = "nullifier-conn-limit";
const REASON_OVER_SPEND_SLASHED: &str = "over-spend-slashed";
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const ROOT_ADVERT_MAX: usize = 16;

pub struct ShadeNode {
    config: Config,
}

struct Shared {
    config: Config,
    connections: Option<Semaphore>,
    per_nullifier: Mutex<HashMap<String, usize>>,
    verifier: Verifier,
    members: Arc<MemberSet>,
    spent: Arc<SpentSet>,
    budget: Arc<Budget>,
    receipts: Option<receipt::Signer>,
}

impl ShadeNode {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Serve until SIGTERM or SIGINT, then drain open connections for the configured grace.
    pub async fn run(self) -> Result<(), Error> {
        let config = self.config;
        let members = Arc::new(MemberSet::load(
            config.members_file().clone(),
            config.rln_identifier().clone(),
        )?);
        let receipts = match config.identity_file() {
            Some(path) => match receipt::Signer::load(path) {
                Ok(signer) => {
                    tracing::info!("egress receipts enabled (signer: onion control key)");
                    Some(signer)
                }
                Err(e) => {
                    tracing::warn!("receipts requested (SHADE_TREE_RECEIPTS=1) but identity unavailable; receipts DISABLED: {e}");
                    None
                }
            },
            None => None,
        };
        let spent = Arc::new(SpentSet::new(
            config.epoch_seconds(),
            config.replay_window(),
            config.spent_state_file().cloned(),
        ));
        let budget = Arc::new(Budget::new(
            config.max_payload_bytes(),
            config.epoch_seconds(),
        ));
        let verifier = Verifier::new(
            config.artifacts(),
            config.epoch_seconds(),
            config.rln_identifier().clone(),
        );
        tracing::info!(
            "accepted artifacts: {}",
            verifier.artifacts().ids().join(",")
        );
        tracing::info!("slash: DRY-RUN (on-chain submission is not part of this build)");

        let addr = config.listen();
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| Error::Bind { addr, source })?;
        let bound = listener
            .local_addr()
            .map_err(|source| Error::LocalAddr { addr, source })?;
        let mut shutdown = Shutdown::install()?;
        let shared = Arc::new(Shared {
            connections: config.max_connections().map(Semaphore::new),
            per_nullifier: Mutex::new(HashMap::new()),
            verifier,
            members: Arc::clone(&members),
            spent: Arc::clone(&spent),
            budget,
            receipts,
            config,
        });
        let mut background = JoinSet::new();
        background.spawn(members.watch());
        background.spawn(async move { spent.flush_periodically().await });
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
        background.abort_all();
        tracing::info!(
            "{signal} received; draining {} connections",
            connections.len()
        );
        let grace = shared.config.shutdown_timeout();
        let drained = tokio::time::timeout(grace, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        shared.spent.flush();
        if drained.is_err() {
            let open = connections.len();
            connections.abort_all();
            return Err(Error::DrainTimeout { open, grace });
        }
        Ok(())
    }
}

/// One nullifier's share of the per-nullifier connection cap, released on drop.
struct NullifierSlot {
    shared: Arc<Shared>,
    nullifier: String,
}

impl NullifierSlot {
    fn acquire(shared: &Arc<Shared>, nullifier: &str) -> Option<Self> {
        if let Some(cap) = shared.config.max_connections_per_nullifier() {
            let mut open = shared
                .per_nullifier
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let count = open.entry(nullifier.to_string()).or_insert(0);
            if *count >= cap {
                return None;
            }
            *count += 1;
        }
        Some(Self {
            shared: Arc::clone(shared),
            nullifier: nullifier.to_string(),
        })
    }
}

impl Drop for NullifierSlot {
    fn drop(&mut self) {
        if self.shared.config.max_connections_per_nullifier().is_none() {
            return;
        }
        let mut open = self
            .shared
            .per_nullifier
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.nullifier) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.nullifier);
            }
        }
    }
}

async fn serve(shared: Arc<Shared>, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _permit = match &shared.connections {
        Some(limit) => match limit.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                tracing::debug!(reason = REASON_TOO_MANY_CONNECTIONS, "tunnel rejected");
                refuse(&mut stream, &refusal(REASON_TOO_MANY_CONNECTIONS, &[])).await;
                return;
            }
        },
        None => None,
    };
    let (envelope, early) = match read_envelope(&mut stream, shared.config.envelope_timeout()).await
    {
        Ok(read) => read,
        Err(e) => {
            tracing::debug!(reason = e.label(), "tunnel rejected");
            refuse(&mut stream, &refusal(&format!("bad-envelope:{e}"), &[])).await;
            return;
        }
    };
    if let Err(e) = accept_envelope_version(&envelope::version(&envelope), (PROTO_MIN, PROTO_MAX)) {
        let reason = e.to_string();
        tracing::debug!(reason, "tunnel rejected");
        let proto = format!("{{\"min\":{PROTO_MIN},\"max\":{PROTO_MAX}}}");
        refuse(&mut stream, &refusal(&reason, &[("proto", proto)])).await;
        return;
    }
    if envelope.get("session").is_some() || envelope.get("ticket").is_some() {
        tracing::debug!(reason = REASON_SESSION_UNSUPPORTED, "tunnel rejected");
        refuse(&mut stream, &refusal(REASON_SESSION_UNSUPPORTED, &[])).await;
        return;
    }
    let target = match shared.config.egress().check_target(envelope.get("target")) {
        Ok(target) => target,
        Err(reason) => {
            tracing::debug!(reason, "tunnel rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };

    let verified = match shared
        .verifier
        .verify(&envelope, &shared.members.roots())
        .await
    {
        Ok(verified) => verified,
        Err(Refusal::Reason(reason)) => {
            tracing::debug!(reason, "tunnel rejected");
            refuse(&mut stream, &refusal(&format!("gate:{reason}"), &[])).await;
            return;
        }
        Err(Refusal::WrongRoot) => {
            tracing::debug!(reason = "wrong-group-root", "tunnel rejected");
            let roots: Vec<String> = shared
                .members
                .roots()
                .into_iter()
                .take(ROOT_ADVERT_MAX)
                .collect();
            let roots = serde_json::to_string(&roots).unwrap_or_else(|_| "[]".into());
            refuse(
                &mut stream,
                &refusal("gate:wrong-group-root", &[("roots", roots)]),
            )
            .await;
            return;
        }
        Err(Refusal::Artifact { reason, ids }) => {
            tracing::debug!(reason, "tunnel rejected");
            let ids = serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into());
            refuse(
                &mut stream,
                &refusal(&format!("gate:{reason}"), &[("artifacts", ids)]),
            )
            .await;
            return;
        }
    };

    let share = Share {
        x: verified.share_x.clone(),
        y: verified.share_y.clone(),
    };
    let nonce = envelope.get("nonce").and_then(|v| v.as_str());
    match shared.spent.admit(&verified.nullifier, share, nonce) {
        Admission::First | Admission::Replay => {}
        Admission::Refused(reason) => {
            tracing::debug!(reason, "tunnel rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
        Admission::OverSpend { first, second } => {
            match slash::reconstruct_secret(&first, &second) {
                Ok(secret) => {
                    let tier = slash::resolve_tier(
                        secret,
                        shared.config.tiers(),
                        shared.config.slots(),
                        |leaf| shared.members.has_leaf(leaf),
                    );
                    slash::dry_run(&tier);
                }
                Err(e) => tracing::error!(reason = "slash-submit-failed", "slash failed: {e}"),
            }
            tracing::debug!(reason = REASON_OVER_SPEND_SLASHED, "tunnel rejected");
            refuse(&mut stream, &refusal(REASON_OVER_SPEND_SLASHED, &[])).await;
            return;
        }
    }

    let Some(_nullifier_slot) = NullifierSlot::acquire(&shared, &verified.nullifier) else {
        tracing::debug!(reason = REASON_NULLIFIER_CONN_LIMIT, "tunnel rejected");
        refuse(&mut stream, &refusal(REASON_NULLIFIER_CONN_LIMIT, &[])).await;
        return;
    };

    let key = Budget::key(&verified.external_nullifier, &verified.nullifier);
    let Some(hold) = shared.budget.acquire(key) else {
        tracing::debug!(
            reason = shadenet_proto::REASON_PAYLOAD_LIMIT,
            "tunnel rejected"
        );
        refuse(
            &mut stream,
            &refusal(shadenet_proto::REASON_PAYLOAD_LIMIT, &[]),
        )
        .await;
        return;
    };

    let candidates = match egress::resolve(
        &target,
        shared.config.allow_private_targets(),
        shared.config.dns_timeout(),
    )
    .await
    {
        Ok(candidates) => candidates,
        Err(reason) => {
            tracing::debug!(reason, "tunnel rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };
    let upstream = match egress::dial(&candidates, shared.config.idle_timeout()).await {
        Ok(upstream) => upstream,
        Err(reason) => {
            tracing::debug!(reason, "tunnel rejected");
            refuse(&mut stream, &refusal(&reason, &[])).await;
            return;
        }
    };
    tracing::debug!(port = target.port, "tunnel established");
    let ack = match &shared.receipts {
        Some(signer) => signer.ack(shared.verifier.current_epoch()),
        None => "{\"ok\":true}".to_string(),
    };
    if !write_line(&mut stream, &ack).await {
        return;
    }
    let close = tunnel::relay(stream, upstream, early, hold, shared.config.idle_timeout()).await;
    tracing::debug!(reason = close.label(), "tunnel closed");
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
