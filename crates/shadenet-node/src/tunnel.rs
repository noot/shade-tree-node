//! The relay after the acknowledgement (`gateway.mjs` `establishTunnel`, `makePayloadBudget`,
//! `payloadTransform`): both directions share one combined byte allowance per admitted
//! `(externalNullifier, nullifier)` slot, one idle timer covers both, and the boundary chunk
//! is delivered before the tunnel closes at the limit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

const CHUNK: usize = 16 * 1024;

struct Allowance {
    used: u64,
    active: usize,
    idle_since: Instant,
}

/// Combined payload allowance per slot. Entries outlive their last tunnel by `ttl` so a retry
/// on the same slot shares what remains.
pub(crate) struct Budget {
    max_bytes: u64,
    ttl: Duration,
    entries: Mutex<HashMap<String, Allowance>>,
}

/// Holds one slot's allowance open for the life of a tunnel.
pub(crate) struct Hold {
    budget: Arc<Budget>,
    key: String,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut entries = self
            .budget
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(&self.key) {
            entry.active = entry.active.saturating_sub(1);
            if entry.active == 0 {
                entry.idle_since = Instant::now();
            }
        }
    }
}

impl Budget {
    /// `max_bytes == 0` means unlimited.
    pub(crate) fn new(max_bytes: u64, epoch_seconds: u64) -> Self {
        Self {
            max_bytes,
            ttl: Duration::from_secs(2 * epoch_seconds),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn key(external_nullifier: &str, nullifier: &str) -> String {
        format!("{external_nullifier}\0{nullifier}")
    }

    /// Open the slot for one more tunnel. `None` when the allowance is already spent.
    pub(crate) fn acquire(self: &Arc<Self>, key: String) -> Option<Hold> {
        if self.max_bytes == 0 {
            return Some(Hold {
                budget: Arc::clone(self),
                key,
            });
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        entries.retain(|_, e| e.active > 0 || now.duration_since(e.idle_since) < self.ttl);
        let entry = entries.entry(key.clone()).or_insert(Allowance {
            used: 0,
            active: 0,
            idle_since: now,
        });
        entry.active += 1;
        if entry.used >= self.max_bytes {
            drop(entries);
            drop(Hold {
                budget: Arc::clone(self),
                key,
            });
            return None;
        }
        Some(Hold {
            budget: Arc::clone(self),
            key,
        })
    }

    /// Admit up to `requested` bytes. Returns how many may be forwarded and whether the slot
    /// is now exhausted.
    fn take(&self, key: &str, requested: usize) -> (usize, bool) {
        if self.max_bytes == 0 {
            return (requested, false);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get_mut(key) else {
            return (0, true);
        };
        let remaining = self.max_bytes.saturating_sub(entry.used);
        let allowed = usize::try_from(remaining).map_or(requested, |r| r.min(requested));
        entry.used += allowed as u64;
        (allowed, entry.used >= self.max_bytes)
    }
}

/// How an established tunnel ended, for the close log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Close {
    /// Both directions reached end of stream.
    Peer,
    IdleTimeout,
    PayloadLimit,
    UpstreamError,
    ClientError,
}

impl Close {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::IdleTimeout => "idle-timeout",
            Self::PayloadLimit => "payload-limit",
            Self::UpstreamError => "upstream-error",
            Self::ClientError => "client-error",
        }
    }
}

enum Pump {
    Eof,
    Limit,
    Failed,
}

#[derive(Clone, Copy)]
enum Direction {
    AgentToDestination,
    DestinationToAgent,
}

struct Activity(AtomicU64, Instant);

impl Activity {
    fn touch(&self) {
        let elapsed = u64::try_from(self.1.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.0.store(elapsed, Ordering::Relaxed);
    }

    fn since_last(&self) -> Duration {
        let last = Duration::from_millis(self.0.load(Ordering::Relaxed));
        self.1.elapsed().saturating_sub(last)
    }
}

/// Relay until a side ends, the idle timer fires, or the allowance runs out. `early` is the
/// client data that arrived with the envelope and goes to the destination first.
pub(crate) async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    early: Vec<u8>,
    hold: Hold,
    idle_timeout: Option<Duration>,
) -> Close {
    let budget = Arc::clone(&hold.budget);
    let key = Arc::new(hold.key.clone());
    let activity = Arc::new(Activity(AtomicU64::new(0), Instant::now()));
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let mut pumps = JoinSet::new();
    pumps.spawn(pump(
        Direction::AgentToDestination,
        client_read,
        upstream_write,
        early,
        Arc::clone(&budget),
        Arc::clone(&key),
        Arc::clone(&activity),
    ));
    pumps.spawn(pump(
        Direction::DestinationToAgent,
        upstream_read,
        client_write,
        Vec::new(),
        budget,
        key,
        Arc::clone(&activity),
    ));
    let close = loop {
        let idle = async {
            match idle_timeout {
                Some(limit) => loop {
                    let since = activity.since_last();
                    if since >= limit {
                        break;
                    }
                    tokio::time::sleep(limit - since).await;
                },
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            joined = pumps.join_next() => match joined {
                None => break Close::Peer,
                Some(Ok((_, Pump::Eof))) => continue,
                Some(Ok((_, Pump::Limit))) => break Close::PayloadLimit,
                Some(Ok((Direction::AgentToDestination, Pump::Failed))) => break Close::ClientError,
                Some(Ok((Direction::DestinationToAgent, Pump::Failed))) => break Close::UpstreamError,
                Some(Err(_)) => break Close::ClientError,
            },
            () = idle => break Close::IdleTimeout,
        }
    };
    pumps.abort_all();
    drop(hold);
    close
}

async fn pump(
    direction: Direction,
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    early: Vec<u8>,
    budget: Arc<Budget>,
    key: Arc<String>,
    activity: Arc<Activity>,
) -> (Direction, Pump) {
    let mut chunk = vec![0_u8; CHUNK];
    let mut pending = early;
    loop {
        if !pending.is_empty() {
            let (allowed, exhausted) = budget.take(&key, pending.len());
            if allowed > 0 {
                if writer.write_all(&pending[..allowed]).await.is_err() {
                    return (direction, Pump::Failed);
                }
                activity.touch();
            }
            if exhausted {
                let _ = writer.flush().await;
                return (direction, Pump::Limit);
            }
            pending.clear();
        }
        match reader.read(&mut chunk).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return (direction, Pump::Eof);
            }
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(_) => return (direction, Pump::Failed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowance_is_shared_and_remembered_until_the_ttl() {
        let budget = Arc::new(Budget::new(10, 1));
        let key = Budget::key("e", "n");
        let hold = budget.acquire(key.clone()).unwrap();
        assert_eq!(budget.take(&key, 6), (6, false));
        assert_eq!(budget.take(&key, 6), (4, true));
        assert_eq!(budget.take(&key, 1), (0, true));
        drop(hold);
        assert!(
            budget.acquire(key.clone()).is_none(),
            "spent slots stay spent"
        );
        std::thread::sleep(Duration::from_millis(2100));
        assert!(
            budget.acquire(key).is_some(),
            "the slot is forgotten after two epochs"
        );
    }

    #[test]
    fn an_unlimited_budget_never_exhausts() {
        let budget = Arc::new(Budget::new(0, 1));
        let key = Budget::key("e", "n");
        let _hold = budget.acquire(key.clone()).unwrap();
        assert_eq!(budget.take(&key, usize::MAX), (usize::MAX, false));
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_and_the_limit_closes_the_tunnel() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = listener.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0_u8; 64];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                socket.write_all(b"pong").await.unwrap();
            }
            got
        });
        let (client, mut agent) = tokio::io::duplex(1024);
        let client = {
            let agent_side = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = agent_side.local_addr().unwrap();
            let connect = TcpStream::connect(addr);
            let (accepted, connected) = tokio::join!(agent_side.accept(), connect);
            let (server_end, _) = accepted.unwrap();
            let client_end = connected.unwrap();
            tokio::spawn(async move {
                let (mut cr, mut cw) = client_end.into_split();
                let (mut dr, mut dw) = tokio::io::split(client);
                tokio::join!(
                    async {
                        let _ = tokio::io::copy(&mut dr, &mut cw).await;
                        let _ = cw.shutdown().await;
                    },
                    async {
                        let _ = tokio::io::copy(&mut cr, &mut dw).await;
                        let _ = dw.shutdown().await;
                    }
                );
            });
            server_end
        };
        let upstream = TcpStream::connect(sink_addr).await.unwrap();
        let budget = Arc::new(Budget::new(12, 60));
        let hold = budget.acquire(Budget::key("e", "n")).unwrap();
        let relay = tokio::spawn(relay(client, upstream, b"early".to_vec(), hold, None));
        let mut reply = [0_u8; 4];
        agent.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        agent.write_all(b"more-than-the-limit").await.unwrap();
        assert_eq!(relay.await.unwrap(), Close::PayloadLimit);
        let got = sink.await.unwrap();
        assert_eq!(got, b"earlymor", "5 early + 4 pong + 3 more = 12 bytes");
    }
}
