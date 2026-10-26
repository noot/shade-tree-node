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

use crate::chain::ChainSource;
use crate::config::Config;
use crate::egress;
use crate::envelope::{self, read_envelope, refusal, refuse, write_line};
use crate::error::Error;
use crate::members::MemberSet;
use crate::receipt;
use crate::roots::Roots;
use crate::rpc::Rpc;
use crate::session;
use crate::slash::{self, SlashConfig, Slasher};
use crate::spent::{Admission, Share, SpentSet};
use crate::tunnel::{self, Budget};
use crate::verify::{Binding, Refusal, Verified, Verifier};

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
    roots: Roots,
    slasher: Slasher,
    spent: Arc<SpentSet>,
    budget: Arc<Budget>,
    receipts: Option<receipt::Signer>,
    sessions: Option<Sessions>,
}

struct Sessions {
    onion: String,
    books: Arc<session::Books>,
}

impl ShadeNode {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Serve until SIGTERM or SIGINT, then drain open connections for the configured grace.
    pub async fn run(self) -> Result<(), Error> {
        let config = self.config;
        let members = match config.members_file() {
            Some(path) => Some(Arc::new(MemberSet::load(
                path.clone(),
                config.rln_identifier().clone(),
            )?)),
            None => None,
        };
        let rln_id = config
            .rln_identifier()
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(1);
        let mut rpc = None;
        let chain = match config.chain() {
            Some(chain_config) => {
                let client = Arc::new(
                    Rpc::new(
                        chain_config.rpc_urls.clone(),
                        chain_config.rpc_timeout,
                        chain_config.rpc_retries,
                    )
                    .map_err(|message| Error::Setting {
                        name: "SHADE_TREE_RPC_URL",
                        message,
                    })?,
                );
                rpc = Some(Arc::clone(&client));
                let source = Arc::new(ChainSource::new(
                    client,
                    chain_config.contracts.clone(),
                    chain_config.root_freshness,
                    chain_config.confirmations,
                    chain_config.logs_chunk,
                    rln_id,
                ));
                let healthy = source.refresh().await;
                if healthy == 0 && members.is_none() {
                    return Err(Error::NoAdmissionRoot(
                        "every on-chain root source failed its first read and no member file is admitted"
                            .into(),
                    ));
                }
                if healthy < chain_config.contracts.len() {
                    tracing::warn!(
                        "{} of {} on-chain root sources failed their first read; serving with the rest and retrying",
                        chain_config.contracts.len() - healthy,
                        chain_config.contracts.len()
                    );
                }
                Some(source)
            }
            None => None,
        };
        let roots = Roots::new(members.clone(), chain.clone());
        let slasher = Slasher::setup(
            SlashConfig {
                key: config.slash_key().map(str::to_string),
                primary: config.slash_contract().map(str::to_string),
                receiver: config.slash_receiver().map(str::to_string),
                admitted: chain
                    .as_ref()
                    .map(|c| {
                        c.contracts()
                            .into_iter()
                            .map(|c| (c.address, c.kind))
                            .collect()
                    })
                    .unwrap_or_default(),
                tiers: config.tiers().to_vec(),
                default_limit: config.slots(),
            },
            rpc,
        )
        .await
        .map_err(Error::Slash)?;
        let identity = match config.identity_file() {
            Some(path) => {
                match receipt::Signer::load(path) {
                    Ok(identity) => Some(identity),
                    Err(e) => {
                        tracing::warn!("onion identity unavailable; receipts and session tickets DISABLED: {e}");
                        None
                    }
                }
            }
            None => None,
        };
        let sessions = match (config.sessions(), &identity) {
            (Some(settings), Some(identity)) => {
                tracing::info!(
                    onion = identity.onion(),
                    classes = session::CLASSES.map(|c| c.class).join(","),
                    "session tickets enabled"
                );
                Some(Sessions {
                    onion: identity.onion(),
                    books: Arc::new(session::Books::new(
                        settings.max_sessions,
                        settings.stream_max,
                    )),
                })
            }
            _ => None,
        };
        let receipts = match (config.receipts(), identity) {
            (true, Some(identity)) => {
                tracing::info!("egress receipts enabled (signer: onion control key)");
                Some(identity)
            }
            _ => None,
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
            roots,
            slasher,
            spent: Arc::clone(&spent),
            budget,
            receipts,
            sessions,
            config,
        });
        let mut background = JoinSet::new();
        if let Some(members) = members {
            background.spawn(members.watch());
        }
        if let Some(chain) = chain {
            background.spawn(chain.poll());
        }
        if let Some(sessions) = &shared.sessions {
            background.spawn(Arc::clone(&sessions.books).sweep());
        }
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
        let Some(sessions) = &shared.sessions else {
            tracing::debug!(reason = REASON_SESSION_UNSUPPORTED, "tunnel rejected");
            refuse(&mut stream, &refusal(REASON_SESSION_UNSUPPORTED, &[])).await;
            return;
        };
        if envelope.get("session").is_some() {
            session_init(&shared, sessions, stream, &envelope).await;
        } else {
            ticket_spend(&shared, sessions, stream, &envelope, early).await;
        }
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
        .verify(&envelope, &shared.roots.accepted(), Binding::Target)
        .await
    {
        Ok(verified) => verified,
        Err(refusal) => {
            refuse_verification(&shared, &mut stream, refusal).await;
            return;
        }
    };

    let nonce = envelope.get("nonce").and_then(|v| v.as_str());
    if let Err(reason) = admit(&shared, &verified, nonce) {
        tracing::debug!(reason, "tunnel rejected");
        refuse(&mut stream, &refusal(reason, &[])).await;
        return;
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
    let close = tunnel::relay(
        stream,
        upstream,
        early,
        hold,
        shared.config.idle_timeout(),
        None,
        None,
    )
    .await;
    tracing::debug!(reason = close.label(), "tunnel closed");
}

/// Every verification refusal's wire form, shared by the tunnel and session paths.
async fn refuse_verification(shared: &Shared, stream: &mut TcpStream, refusal_: Refusal) {
    match refusal_ {
        Refusal::Reason(reason) => {
            tracing::debug!(reason, "tunnel rejected");
            refuse(stream, &refusal(&format!("gate:{reason}"), &[])).await;
        }
        Refusal::WrongRoot => {
            tracing::debug!(reason = "wrong-group-root", "tunnel rejected");
            let extras = shared.roots.advert(ROOT_ADVERT_MAX);
            refuse(stream, &refusal("gate:wrong-group-root", &extras)).await;
        }
        Refusal::Artifact { reason, ids } => {
            tracing::debug!(reason, "tunnel rejected");
            let ids = serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into());
            refuse(
                stream,
                &refusal(&format!("gate:{reason}"), &[("artifacts", ids)]),
            )
            .await;
        }
    }
}

/// The spent set's verdict on a verified proof; an over-spend is slashed here.
fn admit(shared: &Shared, verified: &Verified, nonce: Option<&str>) -> Result<(), &'static str> {
    let share = Share {
        x: verified.share_x.clone(),
        y: verified.share_y.clone(),
    };
    match shared.spent.admit(&verified.nullifier, share, nonce) {
        Admission::First | Admission::Replay => Ok(()),
        Admission::Refused(reason) => Err(reason),
        Admission::OverSpend { first, second } => {
            match slash::reconstruct_secret(&first, &second) {
                Ok(secret) => {
                    let tier = slash::resolve_tier(
                        secret,
                        shared.config.tiers(),
                        shared.config.slots(),
                        |leaf| shared.roots.has_leaf(leaf),
                    );
                    shared.slasher.submit(secret, tier);
                }
                Err(e) => tracing::error!(reason = "slash-submit-failed", "slash failed: {e}"),
            }
            Err(REASON_OVER_SPEND_SLASHED)
        }
    }
}

/// A session initialization: the same cheap-first order as a tunnel, then a book is opened and
/// the ack echoes the policy. The socket is closed after the ack; a book, not a connection, is
/// the session handle.
async fn session_init(
    shared: &Arc<Shared>,
    sessions: &Sessions,
    mut stream: TcpStream,
    envelope: &serde_json::Value,
) {
    let init = match session::validate_init(&envelope["session"]) {
        Ok(init) => init,
        Err(reason) => {
            tracing::debug!(reason, "session rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };
    if init.gateway != sessions.onion {
        tracing::debug!(reason = "session-wrong-gateway", "session rejected");
        refuse(&mut stream, &refusal("session-wrong-gateway", &[])).await;
        return;
    }
    let signal = match shadenet_proto::session::session_signal(
        &init.gateway,
        &init.class,
        &init.nonce,
        &init.digest,
    ) {
        Ok(signal) => signal,
        Err(_) => {
            refuse(&mut stream, &refusal("session-malformed", &[])).await;
            return;
        }
    };
    let verified = match shared
        .verifier
        .verify(envelope, &shared.roots.accepted(), Binding::Signal(signal))
        .await
    {
        Ok(verified) => verified,
        Err(refusal) => {
            refuse_verification(shared, &mut stream, refusal).await;
            return;
        }
    };
    if let Err(reason) = admit(shared, &verified, Some(&init.nonce)) {
        tracing::debug!(reason, "session rejected");
        refuse(&mut stream, &refusal(reason, &[])).await;
        return;
    }
    let opened = match sessions
        .books
        .open(&init, &verified.nullifier, &verified.external_nullifier)
    {
        Ok(opened) => opened,
        Err(reason) => {
            tracing::debug!(reason, "session rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };
    tracing::debug!(
        class = init.class,
        replay = matches!(opened, session::Opened::Replay),
        "session opened"
    );
    let ack = format!(
        "{{\"ok\":true,\"session\":{{\"ticketBookDigest\":\"{}\",\"policy\":{}}}}}",
        init.digest,
        session::policy_echo(init.policy, sessions.books.stream_max())
    );
    refuse(&mut stream, &ack).await;
}

/// A ticket spend: grammar, target policy, the synchronous reservation, then the shared DNS,
/// dial and relay path under the book's budget key, shapers and idle clock.
async fn ticket_spend(
    shared: &Arc<Shared>,
    sessions: &Sessions,
    mut stream: TcpStream,
    envelope: &serde_json::Value,
    early: Vec<u8>,
) {
    let ticket = match session::validate_ticket(&envelope["ticket"]) {
        Ok(ticket) => ticket,
        Err(reason) => {
            tracing::debug!(reason, "ticket rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };
    let target = match shared.config.egress().check_target(envelope.get("target")) {
        Ok(target) => target,
        Err(reason) => {
            tracing::debug!(reason, "ticket rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };
    let target_text = format!("{}:{}", target.host, target.port);
    let reservation = match sessions.books.reserve(&ticket, &target_text) {
        Ok(reservation) => reservation,
        Err(reason) => {
            tracing::debug!(reason, "ticket rejected");
            refuse(&mut stream, &refusal(reason, &[])).await;
            return;
        }
    };
    let books = Arc::clone(&sessions.books);
    let (epoch, nullifier) = &reservation.slot_key;
    let Some(hold) = shared.budget.acquire(Budget::key(epoch, nullifier)) else {
        tracing::debug!(
            reason = shadenet_proto::REASON_PAYLOAD_LIMIT,
            "ticket rejected"
        );
        books.stream_closed(&reservation);
        refuse(
            &mut stream,
            &refusal(shadenet_proto::REASON_PAYLOAD_LIMIT, &[]),
        )
        .await;
        return;
    };
    let cancel = Arc::clone(&reservation.cancel);
    let dialed = tokio::select! {
        dialed = async {
            let candidates = egress::resolve(
                &target,
                shared.config.allow_private_targets(),
                shared.config.dns_timeout(),
            )
            .await
            .map_err(|reason| (reason.to_string(), true))?;
            egress::dial(&candidates, shared.config.idle_timeout())
                .await
                .map_err(|reason| {
                    let definite = reason != "upstream:ETIMEDOUT";
                    (reason, definite)
                })
        } => dialed,
        () = cancel.notified() => {
            books.stream_closed(&reservation);
            return;
        }
    };
    let upstream = match dialed {
        Ok(upstream) => upstream,
        Err((reason, definite)) => {
            tracing::debug!(reason, "ticket rejected");
            if definite {
                books.release(&reservation);
            } else {
                books.stream_closed(&reservation);
            }
            refuse(&mut stream, &refusal(&reason, &[])).await;
            return;
        }
    };
    if !books.spend(&reservation) {
        books.stream_closed(&reservation);
        return;
    }
    tracing::debug!(port = target.port, "tunnel established");
    if !write_line(&mut stream, "{\"ok\":true}").await {
        books.stream_closed(&reservation);
        return;
    }
    let close = tunnel::relay(
        stream,
        upstream,
        early,
        hold,
        shared.config.idle_timeout(),
        Some(Arc::clone(&reservation.shaping)),
        Some(cancel),
    )
    .await;
    tracing::debug!(reason = close.label(), "tunnel closed");
    if close == tunnel::Close::PayloadLimit {
        books.close_book(&reservation.book, "payload-limit");
    }
    books.stream_closed(&reservation);
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
