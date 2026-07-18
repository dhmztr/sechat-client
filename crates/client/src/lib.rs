use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use crypto::{
    Author, Keys, Message, PeerPublic, decrypt_keyfile, delete_peer, encrypt_keyfile,
    generate_ed25519, generate_x25519, identity_hash, initialize_peer, insert_message_stored,
    load_peer_chat_file, load_peer_chat_messages, load_peer_data, load_peers, load_storage_key,
    purge_peer_chat, read_keyfile, relay_session_key, sechat_dir,
};
use ed25519_dalek::VerifyingKey;
use p2p::{SessionEvent, Transport, am_i_first, initial_handshake, punch_hole, start_session};
use serverclient::{
    ClientMessage, ClientToServer, ServerEvent, generate_announce_message,
    generate_offline_message, generate_p2p_request, generate_purge_message,
    generate_unannounce_message, get_or_set_my_address, load_online_peers, run_client,
};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use x25519_dalek::PublicKey;

pub fn fingerprint(id: &[u8; 32]) -> String {
    hex::encode(&id[..6])
}

fn server_config_path() -> PathBuf {
    sechat_dir().join("server")
}

pub fn load_server() -> Option<String> {
    std::fs::read_to_string(server_config_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn save_server(addr: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(sechat_dir())?;
    std::fs::write(server_config_path(), addr.trim())?;
    Ok(())
}

pub fn resolve_server() -> Option<String> {
    std::env::var("SECHAT_SERVER")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(load_server)
}

fn aliases_path() -> PathBuf {
    sechat_dir().join("aliases")
}

pub fn load_aliases() -> HashMap<[u8; 32], String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(aliases_path()) {
        for line in content.lines() {
            if let Some((hex_id, name)) = line.split_once('\t') {
                if let Ok(bytes) = hex::decode(hex_id) {
                    if let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        map.insert(id, name.to_string());
                    }
                }
            }
        }
    }
    map
}

pub fn set_alias(id: &[u8; 32], name: &str) -> anyhow::Result<()> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 32 {
        return Err(anyhow!("alias must be 1-32 characters"));
    }
    let mut map = load_aliases();
    map.insert(*id, name.to_string());
    std::fs::create_dir_all(sechat_dir())?;
    let mut out = String::new();
    for (k, v) in &map {
        out.push_str(&hex::encode(k));
        out.push('\t');
        out.push_str(v);
        out.push('\n');
    }
    std::fs::write(aliases_path(), out)?;
    Ok(())
}

pub fn alias_of(id: &[u8; 32]) -> Option<String> {
    load_aliases().get(id).cloned()
}

/// Drop a peer's alias from the local alias file.
pub fn remove_alias(id: &[u8; 32]) -> anyhow::Result<()> {
    let mut map = load_aliases();
    if map.remove(id).is_none() {
        return Ok(());
    }
    let mut out = String::new();
    for (k, v) in &map {
        out.push_str(&hex::encode(k));
        out.push('\t');
        out.push_str(v);
        out.push('\n');
    }
    std::fs::write(aliases_path(), out)?;
    Ok(())
}

pub fn data_dir() -> String {
    sechat_dir().display().to_string()
}

#[derive(Clone, Debug)]
pub struct Contact {
    pub id: [u8; 32],
    pub fingerprint: String,
    pub online: bool,
    pub address: Option<String>,
    pub alias: Option<String>,
}

impl Contact {
    pub fn label(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.fingerprint)
    }
}

#[derive(Clone, Debug)]
pub struct ChatLine {
    pub from_me: bool,
    pub text: String,
    pub timestamp: i64,
}

#[derive(Clone, Debug)]
pub enum AppEvent {
    Connected {
        observed_address: String,
    },
    PeerOnline {
        id: [u8; 32],
    },
    PeerOffline {
        id: [u8; 32],
    },
    MessageArrived {
        peer: [u8; 32],
        from_me: bool,
    },
    HolePunchDenied {
        peer: [u8; 32],
        reason: String,
    },
    SessionUp {
        peer: [u8; 32],
        direct: bool,
    },
    SessionDown {
        peer: [u8; 32],
    },
    /// A P2P connect attempt failed and will be retried after `delay_secs`.
    ConnectRetrying {
        peer: [u8; 32],
        attempt: u32,
        delay_secs: u64,
    },
    /// Gave up connecting after the maximum number of attempts (parked until the
    /// peer comes online again or the user reconnects).
    ConnectGaveUp {
        peer: [u8; 32],
    },
    Disconnected,
    Error(String),
}

enum Command {
    Send {
        peer: [u8; 32],
        text: String,
    },
    Connect {
        peer: [u8; 32],
    },
    Purge {
        peer: [u8; 32],
    },
    RemovePeer {
        peer: [u8; 32],
    },
    /// Announce presence to all known peers now (e.g. right after adding one).
    AnnounceNow,
    SetServer(String),
    Shutdown,
}

// --- P2P connect retry (air-tight, bounded exponential backoff) ---------------

const MAX_CONNECT_ATTEMPTS: u32 = 5;
const RETRY_BACKOFF_CAP_SECS: u64 = 30;
const RETRY_TICK_MS: u64 = 500;

/// A live "I want to be connected to this peer" intent, driven by the retry tick
/// in `orchestrate`. Owned by that single loop — never shared across tasks.
struct ConnectIntent {
    attempts: u32,
    backoff_secs: u64,
    due_at: std::time::Instant,
    online: bool,
}

impl ConnectIntent {
    /// A freshly-armed intent that fires an attempt immediately.
    fn armed(online: bool) -> Self {
        Self {
            attempts: 0,
            backoff_secs: 1,
            due_at: std::time::Instant::now(),
            online,
        }
    }

    /// Reset attempt counter + backoff so retries resume from scratch.
    fn rearm(&mut self) {
        self.attempts = 0;
        self.backoff_secs = 1;
        self.due_at = std::time::Instant::now();
    }
}

/// What the retry tick should do with one intent right now. Pure decision so it
/// is unit-testable without tokio or sockets.
#[derive(Debug, PartialEq, Eq)]
enum RetryAction {
    /// Send a punch request now.
    Punch,
    /// Attempts exhausted — emit `ConnectGaveUp` once, then park.
    GiveUp,
    /// Nothing to do (offline, not due yet, or already parked).
    Wait,
    /// A live session exists — the intent is satisfied.
    Done,
}

fn next_retry_action(
    intent: &ConnectIntent,
    has_session: bool,
    now: std::time::Instant,
) -> RetryAction {
    if has_session {
        return RetryAction::Done;
    }
    if !intent.online {
        return RetryAction::Wait;
    }
    if intent.attempts > MAX_CONNECT_ATTEMPTS {
        return RetryAction::Wait; // parked
    }
    if intent.attempts == MAX_CONNECT_ATTEMPTS {
        return RetryAction::GiveUp;
    }
    if now < intent.due_at {
        return RetryAction::Wait;
    }
    RetryAction::Punch
}

/// Next backoff delay after a punch (doubles, capped).
fn bump_backoff(current: u64) -> u64 {
    (current * 2).min(RETRY_BACKOFF_CAP_SECS)
}

/// Whether `peer` is currently in the online presence cache.
fn peer_is_online(peer: &[u8; 32]) -> bool {
    load_online_peers()
        .unwrap_or_default()
        .iter()
        .any(|p| &identity_hash(&p.keys.public, &p.keys.verifying) == peer)
}

/// Ask the relay to broker a hole-punch to `peer`. Returns whether the request
/// was sent. Errors are logged (and surfaced to the UI) but never fatal.
async fn send_punch_request(
    peer: &[u8; 32],
    keys: &Arc<Keys>,
    server_tx: &mpsc::Sender<ClientToServer>,
    app_tx: &mpsc::UnboundedSender<AppEvent>,
) -> bool {
    let peer_pub = match load_peer_data(peer) {
        Ok(p) => p,
        Err(e) => {
            let _ = app_tx.send(AppEvent::Error(format!("unknown peer: {e}")));
            return false;
        }
    };
    match generate_p2p_request(&peer_pub.public, &keys.x25519_priv) {
        Ok(msg) => {
            serverclient::debug_log!("requesting hole-punch to {}", fingerprint(peer));
            if server_tx
                .send(ClientToServer::new(msg, None))
                .await
                .is_err()
            {
                let _ = app_tx.send(AppEvent::Error("not connected to relay".to_string()));
                return false;
            }
            true
        }
        Err(e) => {
            let _ = app_tx.send(AppEvent::Error(format!("connect request failed: {e}")));
            false
        }
    }
}

/// One pass of the retry tick: drive every connect-intent according to
/// `next_retry_action`, with bounded exponential backoff.
async fn drive_retries(
    intents: &mut HashMap<[u8; 32], ConnectIntent>,
    sessions: &SessionMap,
    keys: &Arc<Keys>,
    server_tx: &mpsc::Sender<ClientToServer>,
    app_tx: &mpsc::UnboundedSender<AppEvent>,
) {
    let now = std::time::Instant::now();
    // Snapshot live-session keys once (avoid locking per peer inside the loop).
    let live: std::collections::HashSet<[u8; 32]> = sessions.lock().await.keys().copied().collect();
    for (peer, intent) in intents.iter_mut() {
        let has_session = live.contains(peer);
        match next_retry_action(intent, has_session, now) {
            RetryAction::Done => {
                // Connected — reset the ladder ONCE so a later drop retries fresh.
                if intent.attempts != 0 || intent.backoff_secs != 1 {
                    intent.rearm();
                }
            }
            RetryAction::Punch => {
                if send_punch_request(peer, keys, server_tx, app_tx).await {
                    // Only advance the ladder when a punch actually left the client.
                    intent.attempts += 1;
                    let _ = app_tx.send(AppEvent::ConnectRetrying {
                        peer: *peer,
                        attempt: intent.attempts,
                        delay_secs: intent.backoff_secs,
                    });
                    intent.due_at = now + std::time::Duration::from_secs(intent.backoff_secs);
                    intent.backoff_secs = bump_backoff(intent.backoff_secs);
                } else {
                    // Relay unreachable / peer unknown: back off (escalating the
                    // delay up to the cap) WITHOUT burning an attempt, so a transient
                    // relay outage never triggers GiveUp yet never hammers the relay.
                    intent.due_at =
                        now + std::time::Duration::from_secs(intent.backoff_secs.max(1));
                    intent.backoff_secs = bump_backoff(intent.backoff_secs);
                }
            }
            RetryAction::GiveUp => {
                serverclient::debug_log!("giving up P2P connect to {}", fingerprint(peer));
                let _ = app_tx.send(AppEvent::ConnectGaveUp { peer: *peer });
                intent.attempts = MAX_CONNECT_ATTEMPTS + 1; // park until re-armed
            }
            RetryAction::Wait => {}
        }
    }
}

#[derive(Clone)]
pub struct Client {
    cmd_tx: mpsc::UnboundedSender<Command>,
    keys: Arc<Keys>,
    my_id: [u8; 32],
    my_fingerprint: String,
}

impl Client {
    pub fn my_id(&self) -> [u8; 32] {
        self.my_id
    }

    pub fn my_fingerprint(&self) -> &str {
        &self.my_fingerprint
    }

    pub fn my_x25519(&self) -> [u8; 32] {
        self.keys.x25519_pub.to_bytes()
    }

    pub fn my_verifying(&self) -> [u8; 32] {
        self.keys.ed25519_verifying.to_bytes()
    }

    pub fn my_keys_hex(&self) -> (String, String) {
        (
            hex::encode(self.my_x25519()),
            hex::encode(self.my_verifying()),
        )
    }

    pub fn send_message(&self, peer: [u8; 32], text: String) {
        let _ = self.cmd_tx.send(Command::Send { peer, text });
    }

    pub fn connect_peer(&self, peer: [u8; 32]) {
        let _ = self.cmd_tx.send(Command::Connect { peer });
    }

    pub fn set_server(&self, addr: String) {
        let _ = self.cmd_tx.send(Command::SetServer(addr));
    }

    pub fn purge(&self, peer: [u8; 32]) {
        let _ = self.cmd_tx.send(Command::Purge { peer });
    }

    /// Remove a peer entirely (delete their keys, chat and alias locally).
    pub fn remove_peer(&self, peer: [u8; 32]) {
        let _ = self.cmd_tx.send(Command::RemovePeer { peer });
    }

    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(Command::Shutdown);
    }

    pub fn add_peer(&self, x25519: [u8; 32], verifying: [u8; 32]) -> anyhow::Result<[u8; 32]> {
        let peer_pub = PublicKey::from(x25519);
        let peer_verifying =
            VerifyingKey::from_bytes(&verifying).map_err(|_| anyhow!("invalid ed25519 key"))?;
        initialize_peer(&peer_pub, &peer_verifying, &self.keys.x25519_priv)
            .map_err(|e| anyhow!("failed to add peer: {e}"))?;
        // Announce presence for the new peer immediately (don't wait for the 15s
        // presence tick) so both sides can discover each other right away.
        let _ = self.cmd_tx.send(Command::AnnounceNow);
        Ok(identity_hash(&peer_pub, &peer_verifying))
    }

    pub fn contacts(&self) -> Vec<Contact> {
        let all = load_peers().unwrap_or_default();
        let online: HashMap<[u8; 32], String> = load_online_peers()
            .unwrap_or_default()
            .into_iter()
            .map(|p| (identity_hash(&p.keys.public, &p.keys.verifying), p.address))
            .collect();
        let aliases = load_aliases();
        all.into_iter()
            .map(|p| {
                let id = identity_hash(&p.public, &p.verifying);
                let address = online.get(&id).cloned();
                Contact {
                    fingerprint: fingerprint(&id),
                    online: address.is_some(),
                    address,
                    alias: aliases.get(&id).cloned(),
                    id,
                }
            })
            .collect()
    }

    pub fn set_alias(&self, id: &[u8; 32], name: &str) -> anyhow::Result<()> {
        set_alias(id, name)
    }

    pub fn resolve_peer(&self, query: &str) -> Option<[u8; 32]> {
        resolve_query(&self.contacts(), query)
    }

    pub fn history(&self, peer: &[u8; 32]) -> anyhow::Result<Vec<ChatLine>> {
        let peer_pub = load_peer_data(peer).map_err(|e| anyhow!("unknown peer: {e}"))?;
        let storage_key = load_storage_key(&peer_pub.public, &self.keys.x25519_priv)
            .map_err(|e| anyhow!("key derivation failed: {e}"))?;
        let messages = load_peer_chat_messages(&peer_pub, storage_key)
            .map_err(|e| anyhow!("failed to read history: {e}"))?;
        Ok(messages
            .data
            .into_iter()
            .map(|m| ChatLine {
                from_me: m.author == Author::You,
                text: m.text,
                timestamp: m.timestamp,
            })
            .collect())
    }

    pub async fn start(
        keys: Keys,
        server_address: String,
    ) -> anyhow::Result<(Client, mpsc::UnboundedReceiver<AppEvent>)> {
        let keys = Arc::new(keys);
        let my_id = identity_hash(&keys.x25519_pub, &keys.ed25519_verifying);

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
        let (app_tx, app_rx) = mpsc::unbounded_channel::<AppEvent>();

        let handle = Client {
            cmd_tx,
            keys: keys.clone(),
            my_id,
            my_fingerprint: fingerprint(&my_id),
        };

        let udp = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| anyhow!("failed to bind p2p udp socket: {e}"))?,
        );

        tokio::spawn(orchestrate(keys, server_address, cmd_rx, app_tx, udp));
        Ok((handle, app_rx))
    }
}

pub fn identity_exists() -> bool {
    sechat_dir().join("identity.key").exists()
}

pub fn unlock(password: &str) -> anyhow::Result<Keys> {
    let file = read_keyfile().context("failed to read identity file")?;
    decrypt_keyfile(password.to_string(), file).map_err(|_| anyhow!("wrong password"))
}

pub fn create_identity(password: &str) -> anyhow::Result<Keys> {
    let (x25519_priv, x25519_pub) = generate_x25519();
    let ed25519_signing = generate_ed25519();
    let ed25519_verifying = ed25519_signing.verifying_key();
    encrypt_keyfile(
        password.to_string(),
        x25519_priv.clone(),
        x25519_pub,
        ed25519_signing.clone(),
    )
    .map_err(|e| anyhow!("failed to write identity: {e}"))?;
    Ok(Keys {
        x25519_priv,
        x25519_pub,
        ed25519_signing,
        ed25519_verifying,
    })
}

struct SessionEntry {
    outbound: mpsc::Sender<String>,
    relay_in: Option<mpsc::Sender<Vec<u8>>>,
}
type SessionMap = Arc<Mutex<HashMap<[u8; 32], SessionEntry>>>;

fn persist_message(
    keys: &Keys,
    peer_pub: &PeerPublic,
    peer_id: &[u8; 32],
    text: String,
    author: Author,
    timestamp: i64,
) -> anyhow::Result<()> {
    let storage_key = load_storage_key(&peer_pub.public, &keys.x25519_priv)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    let db = load_peer_chat_file(peer_id).map_err(|e| anyhow!("open chat db: {e}"))?;
    let msg = Message::from_parts(text, author, timestamp);
    insert_message_stored(msg, storage_key, db).map_err(|e| anyhow!("store message: {e}"))?;
    Ok(())
}

async fn orchestrate(
    keys: Arc<Keys>,
    mut server_address: String,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    app_tx: mpsc::UnboundedSender<AppEvent>,
    udp: Arc<UdpSocket>,
) {
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    // Per-peer connect-intents drive P2P retries; persists across relay reconnects.
    let mut intents: HashMap<[u8; 32], ConnectIntent> = HashMap::new();
    let mut backoff_secs = 1u64;
    let udp_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);

    loop {
        let (srv_ev_tx, mut srv_ev_rx) = mpsc::channel::<ServerEvent>(100);

        let stun_addr = std::env::var("SECHAT_STUN").ok().unwrap_or_else(|| {
            let host = server_address
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(server_address.as_str());
            format!("{host}:3478")
        });
        let announce = p2p::stun_discover(
            &udp,
            &stun_addr,
            keys.x25519_pub.to_bytes(),
            &keys.ed25519_signing,
        )
        .await;
        if let Some(a) = &announce {
            serverclient::debug_log!("stun: observed public address {a}");
        }

        let server_tx = match run_client(
            keys.x25519_pub,
            keys.ed25519_signing.clone(),
            keys.x25519_priv.clone(),
            server_address.clone(),
            srv_ev_tx,
            udp_port,
            announce,
        )
        .await
        {
            Ok(tx) => {
                serverclient::debug_log!("relay connected + authenticated to {server_address}");
                backoff_secs = 1;
                tx
            }
            Err(e) => {
                serverclient::debug_log!("relay connect to {server_address} failed: {e}");
                let _ = app_tx.send(AppEvent::Error(format!("connect failed: {e}")));
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
                continue;
            }
        };

        let mut retry_ticker =
            tokio::time::interval(std::time::Duration::from_millis(RETRY_TICK_MS));

        loop {
            tokio::select! {
                _ = retry_ticker.tick() => {
                    drive_retries(&mut intents, &sessions, &keys, &server_tx, &app_tx).await;
                }
                ev = srv_ev_rx.recv() => {
                    match ev {
                        Some(ServerEvent::Disconnected) | None => {
                            let _ = app_tx.send(AppEvent::Disconnected);
                            break;
                        }
                        Some(event) => {
                            handle_server_event(
                                event, &keys, &sessions, &server_tx, &app_tx, &udp,
                                &mut intents,
                            )
                            .await;
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        None => return,
                        Some(Command::SetServer(addr)) => {
                            server_address = addr;
                            let _ = save_server(&server_address);
                            backoff_secs = 1;
                            break;
                        }
                        Some(Command::Shutdown) => {
                            let ts = chrono::Utc::now().timestamp();
                            if let Ok(peers) = load_peers() {
                                for peer in peers {
                                    if let Ok(msg) = generate_unannounce_message(
                                        &keys.x25519_priv,
                                        &peer.public,
                                        ts,
                                    ) {
                                        let _ = server_tx.send(ClientToServer::new(msg, None)).await;
                                    }
                                }
                            }
                            sessions.lock().await.clear();
                            serverclient::debug_log!("graceful shutdown complete");
                            return;
                        }
                        Some(command) => {
                            handle_command(
                                command, &keys, &sessions, &server_tx, &app_tx, &mut intents,
                            )
                            .await;
                        }
                    }
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(30);
    }
}

async fn handle_server_event(
    event: ServerEvent,
    keys: &Arc<Keys>,
    sessions: &SessionMap,
    server_tx: &mpsc::Sender<ClientToServer>,
    app_tx: &mpsc::UnboundedSender<AppEvent>,
    udp: &Arc<UdpSocket>,
    intents: &mut HashMap<[u8; 32], ConnectIntent>,
) {
    match event {
        ServerEvent::Authenticated { observed_address } => {
            let _ = app_tx.send(AppEvent::Connected { observed_address });
        }
        ServerEvent::RelayData {
            sender_hash,
            payload,
        } => {
            let relay_in = {
                let map = sessions.lock().await;
                map.get(&sender_hash).and_then(|e| e.relay_in.clone())
            };
            if let Some(tx) = relay_in {
                let _ = tx.send(payload).await;
            }
        }
        ServerEvent::PeerOnline { hash, .. } => {
            if let Some(intent) = intents.get_mut(&hash) {
                intent.online = true;
                // Un-park: a peer coming back online re-arms a given-up intent.
                if intent.attempts > MAX_CONNECT_ATTEMPTS {
                    intent.rearm();
                }
            }
            let _ = app_tx.send(AppEvent::PeerOnline { id: hash });
        }
        ServerEvent::PeerOffline { hash } => {
            if let Some(intent) = intents.get_mut(&hash) {
                intent.online = false;
            }
            let _ = app_tx.send(AppEvent::PeerOffline { id: hash });
        }
        ServerEvent::BlobStored { sender_hash } => {
            let _ = app_tx.send(AppEvent::MessageArrived {
                peer: sender_hash,
                from_me: false,
            });
        }
        ServerEvent::HolePunchDenied { peer, reason } => {
            let _ = app_tx.send(AppEvent::HolePunchDenied { peer, reason });
        }
        ServerEvent::PunchHole {
            peer_hash,
            ip_port,
            punchtimestamp,
            ..
        } => {
            // Resolve the peer's keys by identity from disk — robust regardless of
            // whether the peer is currently in the (TTL-pruned) online cache.
            let peer = load_peer_data(&peer_hash).ok().or_else(|| {
                load_online_peers()
                    .unwrap_or_default()
                    .into_iter()
                    .find(|p| p.address == ip_port)
                    .map(|p| p.keys)
            });
            serverclient::debug_log!(
                "punch-hole broker: peer {} at {ip_port} (known: {})",
                fingerprint(&peer_hash),
                peer.is_some()
            );
            if let Some(peer) = peer {
                tokio::spawn(connect_session(
                    keys.clone(),
                    peer,
                    ip_port,
                    punchtimestamp,
                    sessions.clone(),
                    app_tx.clone(),
                    udp.clone(),
                    server_tx.clone(),
                ));
            } else {
                serverclient::debug_log!(
                    "punch-hole for unknown peer {} — ignoring",
                    fingerprint(&peer_hash)
                );
            }
        }
        ServerEvent::Disconnected => {}
    }
}

async fn handle_command(
    command: Command,
    keys: &Arc<Keys>,
    sessions: &SessionMap,
    server_tx: &mpsc::Sender<ClientToServer>,
    app_tx: &mpsc::UnboundedSender<AppEvent>,
    intents: &mut HashMap<[u8; 32], ConnectIntent>,
) {
    match command {
        Command::Connect { peer } => {
            if load_peer_data(&peer).is_err() {
                let _ = app_tx.send(AppEvent::Error("unknown peer".to_string()));
                return;
            }
            // Already have a live session? Keep it — don't reset the ladder or
            // re-punch a working connection.
            if sessions.lock().await.contains_key(&peer) {
                serverclient::debug_log!("already connected to {}", fingerprint(&peer));
                return;
            }
            // Arm a connect-intent; the retry tick drives the actual punch(es)
            // with bounded exponential backoff.
            intents.insert(peer, ConnectIntent::armed(peer_is_online(&peer)));
            serverclient::debug_log!("armed connect-intent for {}", fingerprint(&peer));
        }
        Command::SetServer(_) | Command::Shutdown => {}
        Command::RemovePeer { peer } => {
            // Drop retry-intent + live session, then delete keys, chat and alias.
            intents.remove(&peer);
            sessions.lock().await.remove(&peer);
            if let Err(e) = delete_peer(&peer) {
                let _ = app_tx.send(AppEvent::Error(format!("remove peer failed: {e}")));
                return;
            }
            let _ = remove_alias(&peer);
            serverclient::debug_log!("removed peer {}", fingerprint(&peer));
        }
        Command::AnnounceNow => {
            let Some(address) = get_or_set_my_address(None) else {
                serverclient::debug_log!("announce-now skipped: no address yet");
                return;
            };
            let peers = load_peers().unwrap_or_default();
            let ts = chrono::Utc::now().timestamp();
            for peer in peers {
                if let Ok(msg) =
                    generate_announce_message(&keys.x25519_priv, &peer.public, ts, address.clone())
                {
                    let _ = server_tx.send(ClientToServer::new(msg, None)).await;
                }
            }
            serverclient::debug_log!("announced presence to all peers (add-peer trigger)");
        }
        Command::Purge { peer } => {
            // Stop retrying / drop any live session for a peer we're purging.
            intents.remove(&peer);
            sessions.lock().await.remove(&peer);
            let peer_pub = match load_peer_data(&peer) {
                Ok(p) => p,
                Err(e) => {
                    let _ = app_tx.send(AppEvent::Error(format!("unknown peer: {e}")));
                    return;
                }
            };
            match generate_purge_message(&peer_pub, &keys.x25519_pub, &keys.ed25519_signing) {
                Ok(blob) => {
                    let _ = server_tx.send(blob).await;
                }
                Err(e) => {
                    let _ = app_tx.send(AppEvent::Error(format!("purge send failed: {e}")));
                }
            }
            if let Err(e) = purge_peer_chat(&peer) {
                let _ = app_tx.send(AppEvent::Error(format!("local purge failed: {e}")));
            } else {
                serverclient::debug_log!("purged conversation with {}", fingerprint(&peer));
                let _ = app_tx.send(AppEvent::MessageArrived {
                    peer,
                    from_me: true,
                });
            }
        }
        Command::Send { peer, text } => {
            let peer_pub = match load_peer_data(&peer) {
                Ok(p) => p,
                Err(e) => {
                    let _ = app_tx.send(AppEvent::Error(format!("unknown peer: {e}")));
                    return;
                }
            };

            let live = {
                let map = sessions.lock().await;
                map.get(&peer).map(|e| e.outbound.clone())
            };

            let now = chrono::Utc::now().timestamp();
            if let Some(tx) = live {
                serverclient::debug_log!("sending to {} over live session", fingerprint(&peer));
                if tx.send(text.clone()).await.is_err() {
                    sessions.lock().await.remove(&peer);
                }
            } else {
                serverclient::debug_log!(
                    "no live session with {} — sending as offline blob",
                    fingerprint(&peer)
                );
                match generate_offline_message(
                    &peer_pub,
                    &keys.x25519_pub,
                    &keys.x25519_priv,
                    text.clone(),
                    &keys.ed25519_signing,
                ) {
                    Ok(blob) => {
                        let _ = server_tx.send(blob).await;
                    }
                    Err(e) => {
                        let _ = app_tx.send(AppEvent::Error(format!("send failed: {e}")));
                        return;
                    }
                }
            }

            if persist_message(keys, &peer_pub, &peer, text, Author::You, now).is_ok() {
                let _ = app_tx.send(AppEvent::MessageArrived {
                    peer,
                    from_me: true,
                });
            }
        }
    }
}

fn make_relay(
    peer_id: [u8; 32],
    server_tx: mpsc::Sender<ClientToServer>,
) -> (Transport, mpsc::Sender<Vec<u8>>) {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(100);
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            let msg = ClientMessage::RelayData {
                recipient_hash: peer_id,
                payload,
            };
            if server_tx
                .send(ClientToServer::new(msg, None))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    (
        Transport::Relay {
            out: out_tx,
            inbound: in_rx,
        },
        in_tx,
    )
}

async fn connect_session(
    keys: Arc<Keys>,
    peer: PeerPublic,
    ip_port: String,
    punchtimestamp: i64,
    sessions: SessionMap,
    app_tx: mpsc::UnboundedSender<AppEvent>,
    udp: Arc<UdpSocket>,
    server_tx: mpsc::Sender<ClientToServer>,
) {
    let peer_id = identity_hash(&peer.public, &peer.verifying);
    if sessions.lock().await.contains_key(&peer_id) {
        serverclient::debug_log!(
            "session with {} already active — skipping punch",
            fingerprint(&peer_id)
        );
        return;
    }
    let am_first = am_i_first(keys.x25519_pub.as_bytes(), peer.public.as_bytes());
    let (eph_priv, eph_pub) = generate_x25519();

    let punch = punch_hole(
        &udp,
        punchtimestamp as u64,
        keys.x25519_pub,
        peer.public,
        &ip_port,
    )
    .await;

    let (transport, session_key, relay_in, direct) = match punch {
        Ok(remote) => {
            serverclient::debug_log!("hole punched to {} at {remote}", fingerprint(&peer_id));
            match initial_handshake(
                &keys.x25519_pub,
                &eph_priv,
                &eph_pub.to_bytes(),
                &peer,
                &keys.ed25519_signing,
                &udp,
                remote,
            )
            .await
            {
                Ok(k) => (
                    Transport::Direct {
                        socket: udp.clone(),
                        remote,
                    },
                    k,
                    None,
                    true,
                ),
                Err(_) => {
                    serverclient::debug_log!(
                        "handshake with {} failed — falling back to relay",
                        fingerprint(&peer_id)
                    );
                    let (t, in_tx) = make_relay(peer_id, server_tx.clone());
                    (
                        t,
                        relay_session_key(&peer.public, &keys.x25519_priv),
                        Some(in_tx),
                        false,
                    )
                }
            }
        }
        Err(_) => {
            serverclient::debug_log!("punch to {} timed out — using relay", fingerprint(&peer_id));
            let (t, in_tx) = make_relay(peer_id, server_tx.clone());
            (
                t,
                relay_session_key(&peer.public, &keys.x25519_priv),
                Some(in_tx),
                false,
            )
        }
    };

    let session = start_session(
        transport,
        session_key,
        keys.x25519_pub,
        keys.ed25519_signing.clone(),
        peer.clone(),
        am_first,
    );

    serverclient::debug_log!(
        "session with {} up ({})",
        fingerprint(&peer_id),
        if direct { "direct" } else { "relay" }
    );
    sessions.lock().await.insert(
        peer_id,
        SessionEntry {
            outbound: session.outbound,
            relay_in,
        },
    );
    let _ = app_tx.send(AppEvent::SessionUp {
        peer: peer_id,
        direct,
    });

    let mut events = session.events;
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                SessionEvent::Message { text, timestamp } => {
                    let _ = persist_message(&keys, &peer, &peer_id, text, Author::Peer, timestamp);
                    let _ = app_tx.send(AppEvent::MessageArrived {
                        peer: peer_id,
                        from_me: false,
                    });
                }
                SessionEvent::Closed => break,
            }
        }
        sessions.lock().await.remove(&peer_id);
        let _ = app_tx.send(AppEvent::SessionDown { peer: peer_id });
    });
}

fn resolve_query(contacts: &[Contact], query: &str) -> Option<[u8; 32]> {
    let q = query.trim();
    if q.is_empty() {
        return None;
    }
    contacts
        .iter()
        .find(|c| c.alias.as_deref() == Some(q))
        .or_else(|| {
            contacts
                .iter()
                .find(|c| c.alias.as_deref().is_some_and(|a| a.starts_with(q)))
        })
        .or_else(|| contacts.iter().find(|c| c.fingerprint.starts_with(q)))
        .map(|c| c.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(id: u8, fp: &str, alias: Option<&str>) -> Contact {
        Contact {
            id: [id; 32],
            fingerprint: fp.to_string(),
            online: false,
            address: None,
            alias: alias.map(str::to_string),
        }
    }

    #[test]
    fn resolve_by_exact_alias() {
        let cs = vec![
            contact(1, "aaaa", Some("alice")),
            contact(2, "bbbb", Some("bob")),
        ];
        assert_eq!(resolve_query(&cs, "bob"), Some([2; 32]));
    }

    #[test]
    fn resolve_by_alias_prefix() {
        let cs = vec![contact(1, "aaaa", Some("alice"))];
        assert_eq!(resolve_query(&cs, "al"), Some([1; 32]));
    }

    #[test]
    fn resolve_by_fingerprint_prefix() {
        let cs = vec![contact(7, "deadbeef", None)];
        assert_eq!(resolve_query(&cs, "dead"), Some([7; 32]));
    }

    #[test]
    fn resolve_prefers_exact_alias_over_fingerprint() {
        let cs = vec![
            contact(1, "cafe1234", None),
            contact(2, "ffff", Some("cafe")),
        ];
        assert_eq!(resolve_query(&cs, "cafe"), Some([2; 32]));
    }

    #[test]
    fn resolve_empty_or_unknown_is_none() {
        let cs = vec![contact(1, "aaaa", Some("alice"))];
        assert_eq!(resolve_query(&cs, ""), None);
        assert_eq!(resolve_query(&cs, "zzz"), None);
    }

    // --- P2P retry decision logic ---------------------------------------------

    use std::time::{Duration, Instant};

    fn intent(attempts: u32, backoff: u64, online: bool, due_in: Option<u64>) -> ConnectIntent {
        let now = Instant::now();
        ConnectIntent {
            attempts,
            backoff_secs: backoff,
            online,
            due_at: match due_in {
                Some(s) => now + Duration::from_secs(s),
                None => now, // due now
            },
        }
    }

    #[test]
    fn retry_first_attempt_fires_when_due_and_online() {
        let i = intent(0, 1, true, None);
        assert_eq!(
            next_retry_action(&i, false, Instant::now()),
            RetryAction::Punch
        );
    }

    #[test]
    fn retry_waits_when_offline() {
        let i = intent(0, 1, false, None);
        assert_eq!(
            next_retry_action(&i, false, Instant::now()),
            RetryAction::Wait
        );
    }

    #[test]
    fn retry_waits_when_not_yet_due() {
        let i = intent(1, 2, true, Some(10));
        assert_eq!(
            next_retry_action(&i, false, Instant::now()),
            RetryAction::Wait
        );
    }

    #[test]
    fn retry_done_when_session_live() {
        let i = intent(3, 8, true, None);
        assert_eq!(
            next_retry_action(&i, true, Instant::now()),
            RetryAction::Done
        );
    }

    #[test]
    fn retry_gives_up_at_max_attempts() {
        let i = intent(MAX_CONNECT_ATTEMPTS, 30, true, None);
        assert_eq!(
            next_retry_action(&i, false, Instant::now()),
            RetryAction::GiveUp
        );
    }

    #[test]
    fn retry_parked_past_max_waits() {
        let i = intent(MAX_CONNECT_ATTEMPTS + 1, 30, true, None);
        assert_eq!(
            next_retry_action(&i, false, Instant::now()),
            RetryAction::Wait
        );
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(bump_backoff(1), 2);
        assert_eq!(bump_backoff(2), 4);
        assert_eq!(bump_backoff(16), 32.min(RETRY_BACKOFF_CAP_SECS));
        assert_eq!(bump_backoff(RETRY_BACKOFF_CAP_SECS), RETRY_BACKOFF_CAP_SECS);
    }

    #[test]
    fn rearm_resets_ladder() {
        let mut i = intent(MAX_CONNECT_ATTEMPTS + 1, 30, true, Some(100));
        i.rearm();
        assert_eq!(i.attempts, 0);
        assert_eq!(i.backoff_secs, 1);
        // now due again
        assert_eq!(
            next_retry_action(&i, false, Instant::now()),
            RetryAction::Punch
        );
    }
}
