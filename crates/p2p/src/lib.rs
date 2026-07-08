use chacha20poly1305::Key;
use chrono::Utc;
use crypto::*;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Deserialize, Serialize)]
struct Ping {
    pubkey: [u8; 32],
    timestamp: u64,
}
#[derive(Debug)]
pub enum P2PError {
    CommunicationError,
    Timeout,
    StorageFailed(String),
    SerializationFailed,
    DeserializationFailed,
    CryptographicError,
}
#[derive(Debug)]
pub enum PunchHoleResult {
    SendError,
    RecvError,
    Timeout,
}

#[derive(Serialize, Deserialize)]
pub enum P2PMessage {
    Init {
        ephermal: [u8; 32],
    },
    ChatMessage {
        counter: i64,
        message_bytes: Vec<u8>,
    },
    HeartBeat,
    SyncRequest {
        last_timestamp: i64,
    },
    SyncResponse {
        messages: Vec<u8>,
    },
    End,
}
#[derive(Serialize, Deserialize)]
pub struct PeerMessage {
    timestamp: i64,
    payload: P2PMessage,
    sender: PublicKey,
    signature: Vec<u8>,
}
impl PeerMessage {
    fn new(payload: P2PMessage, sender: &PublicKey, signing: &SigningKey) -> Self {
        let timestamp = Utc::now().timestamp();
        let payload_bytes = match payload {
            P2PMessage::Init { ephermal } => &ephermal.to_vec(),
            P2PMessage::ChatMessage {
                counter,
                ref message_bytes,
            } => &[&counter.to_le_bytes(), message_bytes.as_slice()]
                .concat()
                .to_vec(),
            P2PMessage::End => &"EndOfConversation".as_bytes().to_vec(),
            P2PMessage::HeartBeat => &b"Heartbeat".to_vec(),
            P2PMessage::SyncRequest { last_timestamp } => &last_timestamp.to_le_bytes().to_vec(),
            P2PMessage::SyncResponse { ref messages } => &messages.clone(),
        };
        let data_to_sign = [
            sender.to_bytes().as_slice(),
            timestamp.to_le_bytes().as_slice(),
            &payload_bytes.as_slice(),
        ]
        .concat();
        let signature = sign_challenge(signing, &data_to_sign).to_vec();
        PeerMessage {
            timestamp,
            payload,
            sender: *sender,
            signature,
        }
    }
    fn verify(&self, expected_x25519: &[u8; 32], expected_verifying: &VerifyingKey) -> bool {
        if &self.sender.to_bytes() != expected_x25519 {
            return false;
        }
        let payload_bytes: Vec<u8> = match self.payload {
            P2PMessage::Init { ephermal } => ephermal.to_vec(),
            P2PMessage::ChatMessage {
                counter,
                ref message_bytes,
            } => [&counter.to_le_bytes(), message_bytes.as_slice()].concat(),
            P2PMessage::End => b"EndOfConversation".to_vec(),
            P2PMessage::HeartBeat => b"Heartbeat".to_vec(),
            P2PMessage::SyncRequest { last_timestamp } => last_timestamp.to_le_bytes().to_vec(),
            P2PMessage::SyncResponse { ref messages } => messages.clone(),
        };
        let data_to_verify = [
            self.sender.to_bytes().as_slice(),
            self.timestamp.to_le_bytes().as_slice(),
            payload_bytes.as_slice(),
        ]
        .concat();
        let signature = match Signature::from_slice(self.signature.as_slice()) {
            Ok(sig) => sig,
            _ => return false,
        };
        verify_challenge(*expected_verifying, &data_to_verify, &signature).is_ok()
    }
}
pub async fn punch_hole(
    socket: &UdpSocket,
    timestamp: u64,
    mypubkey: PublicKey,
    remote_pubkey: PublicKey,
    remote_addr: &str,
) -> Result<SocketAddr, PunchHoleResult> {
    let ping = Ping {
        pubkey: mypubkey.to_bytes(),
        timestamp,
    };
    let data = rmp_serde::to_vec(&ping).map_err(|_| PunchHoleResult::SendError)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    let mut buf = [0u8; 1024];

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let _ = socket.send_to(&data, remote_addr).await;
            }
            recvd = socket.recv_from(&mut buf) => {
                match recvd {
                    Ok((len, addr)) => {
                        if let Ok(p) = rmp_serde::from_slice::<Ping>(&buf[..len]) {
                            if p.pubkey == remote_pubkey.to_bytes() && p.timestamp == timestamp {
                                return Ok(addr);
                            }
                        }
                    }
                    Err(_) => return Err(PunchHoleResult::RecvError),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(PunchHoleResult::Timeout);
            }
        }
    }
}

pub fn am_i_first(mypubkey: &[u8; 32], remote_pubkey: &[u8; 32]) -> bool {
    mypubkey > remote_pubkey
}

#[derive(Serialize, Deserialize)]
struct StunPing {
    pub_key: [u8; 32],
    verif: [u8; 32],
    timestamp: i64,
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct StunReply {
    observed: String,
}

pub async fn stun_discover(
    socket: &UdpSocket,
    stun_addr: &str,
    pub_key: [u8; 32],
    signing: &SigningKey,
) -> Option<String> {
    let timestamp = Utc::now().timestamp();
    let verif = signing.verifying_key().to_bytes();
    let data = [
        pub_key.as_slice(),
        verif.as_slice(),
        &timestamp.to_le_bytes(),
    ]
    .concat();
    let signature = sign_challenge(signing, &data).to_vec();
    let ping = StunPing {
        pub_key,
        verif,
        timestamp,
        signature,
    };
    let bytes = rmp_serde::to_vec(&ping).ok()?;

    let mut buf = [0u8; 512];
    for _ in 0..3 {
        if socket.send_to(&bytes, stun_addr).await.is_err() {
            return None;
        }
        if let Ok(Ok((len, _))) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
        {
            if let Ok(reply) = rmp_serde::from_slice::<StunReply>(&buf[..len]) {
                return Some(reply.observed);
            }
        }
    }
    None
}

async fn send_peer_message(
    socket: &UdpSocket,
    remote_addr: SocketAddr,
    payload: P2PMessage,
    my_pub: &PublicKey,
    signing: &SigningKey,
) -> Result<(), P2PError> {
    let msg = PeerMessage::new(payload, my_pub, signing);
    let bytes = rmp_serde::to_vec(&msg).map_err(|_| P2PError::SerializationFailed)?;
    socket
        .send_to(&bytes, remote_addr)
        .await
        .map_err(|_| P2PError::CommunicationError)?;
    Ok(())
}

async fn recv_peer_datagram(
    socket: &UdpSocket,
    buf: &mut [u8],
    remote_addr: SocketAddr,
    secs: u64,
) -> Result<usize, P2PError> {
    loop {
        let (len, addr) = timeout(Duration::from_secs(secs), socket.recv_from(buf))
            .await
            .map_err(|_| P2PError::Timeout)?
            .map_err(|_| P2PError::CommunicationError)?;
        if addr == remote_addr {
            return Ok(len);
        }
    }
}

pub async fn initial_handshake(
    my_pubkey: &PublicKey,
    myephermal_priv: &StaticSecret,
    myephermal_pub: &[u8; 32],
    remote: &PeerPublic,
    my_signing: &SigningKey,
    socket: &UdpSocket,
    remote_addr: SocketAddr,
) -> Result<[u8; 32], P2PError> {
    let remote_x = remote.public.to_bytes();
    let mut buf = [0u8; 1024];
    let amount: usize;

    let init = || P2PMessage::Init {
        ephermal: *myephermal_pub,
    };

    if am_i_first(my_pubkey.as_bytes(), &remote_x) {
        send_peer_message(socket, remote_addr, init(), my_pubkey, my_signing).await?;
        amount = recv_peer_datagram(socket, &mut buf, remote_addr, 5).await?;
    } else {
        amount = recv_peer_datagram(socket, &mut buf, remote_addr, 5).await?;
        send_peer_message(socket, remote_addr, init(), my_pubkey, my_signing).await?;
    }

    let peerinit: PeerMessage =
        rmp_serde::from_slice(&buf[..amount]).map_err(|_| P2PError::DeserializationFailed)?;
    if !peerinit.verify(&remote_x, &remote.verifying) {
        return Err(P2PError::CryptographicError);
    }
    match peerinit.payload {
        P2PMessage::Init { ephermal } => {
            derive_session_key(myephermal_priv, &PublicKey::from(ephermal))
                .map_err(|_| P2PError::CryptographicError)
        }
        _ => Err(P2PError::CommunicationError),
    }
}

#[derive(Debug)]
pub enum SessionEvent {
    Message { text: String, timestamp: i64 },
    Closed,
}

pub struct SessionHandle {
    pub outbound: mpsc::Sender<String>,
    pub events: mpsc::Receiver<SessionEvent>,
}

const HEARTBEAT_SECS: u64 = 15;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 60;

pub enum Transport {
    Direct {
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
    },
    Relay {
        out: mpsc::UnboundedSender<Vec<u8>>,
        inbound: mpsc::Receiver<Vec<u8>>,
    },
}

fn frame(payload: P2PMessage, my_pub: &PublicKey, signing: &SigningKey) -> Option<Vec<u8>> {
    rmp_serde::to_vec(&PeerMessage::new(payload, my_pub, signing)).ok()
}

async fn handle_inbound_frame(
    bytes: &[u8],
    recv_key: Key,
    peer_x: &[u8; 32],
    verifying: &VerifyingKey,
    last_counter: &mut i64,
    evt: &mpsc::Sender<SessionEvent>,
) -> bool {
    let pm: PeerMessage = match rmp_serde::from_slice(bytes) {
        Ok(p) => p,
        Err(_) => return true,
    };
    if !pm.verify(peer_x, verifying) {
        return true;
    }
    match pm.payload {
        P2PMessage::ChatMessage {
            counter,
            message_bytes,
        } => {
            if counter <= *last_counter {
                return true;
            }
            if let Ok(text) = decrypt_message_from_chat(message_bytes, recv_key, counter as u64) {
                *last_counter = counter;
                if evt
                    .send(SessionEvent::Message {
                        text,
                        timestamp: pm.timestamp,
                    })
                    .await
                    .is_err()
                {
                    return false;
                }
            }
            true
        }
        P2PMessage::End => false,
        _ => true,
    }
}

pub fn start_session(
    transport: Transport,
    session_key: [u8; 32],
    my_pub: PublicKey,
    my_signing: SigningKey,
    peer: PeerPublic,
    am_first: bool,
) -> SessionHandle {
    let (out_tx, mut out_rx) = mpsc::channel::<String>(100);
    let (evt_tx, evt_rx) = mpsc::channel::<SessionEvent>(100);

    let (send_label, recv_label): (&[u8], &[u8]) = if am_first {
        (b"a2b", b"b2a")
    } else {
        (b"b2a", b"a2b")
    };
    let send_key = derive_directional_key(&session_key, send_label);
    let recv_key = derive_directional_key(&session_key, recv_label);

    let peer_x = peer.public.to_bytes();
    let verifying = peer.verifying;

    match transport {
        Transport::Direct { socket, remote } => {
            let r_socket = socket.clone();
            let r_evt = evt_tx.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut last_counter: i64 = -1;
                loop {
                    let recvd = timeout(
                        Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS),
                        r_socket.recv_from(&mut buf),
                    )
                    .await;
                    let (len, addr) = match recvd {
                        Ok(Ok(v)) => v,
                        _ => break,
                    };
                    if addr != remote {
                        continue;
                    }
                    if !handle_inbound_frame(
                        &buf[..len],
                        recv_key,
                        &peer_x,
                        &verifying,
                        &mut last_counter,
                        &r_evt,
                    )
                    .await
                    {
                        break;
                    }
                }
                let _ = r_evt.send(SessionEvent::Closed).await;
            });

            tokio::spawn(async move {
                let mut counter: i64 = 0;
                let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
                heartbeat.tick().await;
                loop {
                    tokio::select! {
                        outgoing = out_rx.recv() => match outgoing {
                            Some(text) => {
                                counter += 1;
                                let cipher = encrypt_message_for_chat(text, send_key, counter as u64);
                                let payload = P2PMessage::ChatMessage { counter, message_bytes: cipher };
                                if send_peer_message(&socket, remote, payload, &my_pub, &my_signing).await.is_err() {
                                    break;
                                }
                            }
                            None => {
                                let _ = send_peer_message(&socket, remote, P2PMessage::End, &my_pub, &my_signing).await;
                                break;
                            }
                        },
                        _ = heartbeat.tick() => {
                            if send_peer_message(&socket, remote, P2PMessage::HeartBeat, &my_pub, &my_signing).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        Transport::Relay { out, mut inbound } => {
            let r_evt = evt_tx.clone();
            tokio::spawn(async move {
                let mut last_counter: i64 = -1;
                loop {
                    let bytes = match timeout(
                        Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS),
                        inbound.recv(),
                    )
                    .await
                    {
                        Ok(Some(b)) => b,
                        _ => break,
                    };
                    if !handle_inbound_frame(
                        &bytes,
                        recv_key,
                        &peer_x,
                        &verifying,
                        &mut last_counter,
                        &r_evt,
                    )
                    .await
                    {
                        break;
                    }
                }
                let _ = r_evt.send(SessionEvent::Closed).await;
            });

            tokio::spawn(async move {
                let mut counter: i64 = 0;
                let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
                heartbeat.tick().await;
                loop {
                    tokio::select! {
                        outgoing = out_rx.recv() => match outgoing {
                            Some(text) => {
                                counter += 1;
                                let cipher = encrypt_message_for_chat(text, send_key, counter as u64);
                                if let Some(bytes) = frame(P2PMessage::ChatMessage { counter, message_bytes: cipher }, &my_pub, &my_signing) {
                                    if out.send(bytes).is_err() { break; }
                                }
                            }
                            None => {
                                if let Some(bytes) = frame(P2PMessage::End, &my_pub, &my_signing) {
                                    let _ = out.send(bytes);
                                }
                                break;
                            }
                        },
                        _ = heartbeat.tick() => {
                            if let Some(bytes) = frame(P2PMessage::HeartBeat, &my_pub, &my_signing) {
                                if out.send(bytes).is_err() { break; }
                            }
                        }
                    }
                }
            });
        }
    }

    SessionHandle {
        outbound: out_tx,
        events: evt_rx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ident {
        x_priv: StaticSecret,
        x_pub: PublicKey,
        signing: SigningKey,
        peerpub: PeerPublic,
    }
    fn ident() -> Ident {
        let (x_priv, x_pub) = generate_x25519();
        let signing = generate_ed25519();
        let verifying = signing.verifying_key();
        let peerpub = PeerPublic {
            public: x_pub,
            verifying,
        };
        Ident {
            x_priv,
            x_pub,
            signing,
            peerpub,
        }
    }

    #[tokio::test]
    async fn handshake_and_session_roundtrip() {
        let a = ident();
        let b = ident();
        let (a_eph_priv, a_eph_pub) = generate_x25519();
        let (b_eph_priv, b_eph_pub) = generate_x25519();

        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let a_view_b = b.peerpub.clone();
        let b_view_a = a.peerpub.clone();

        let sa = sock_a.clone();
        let sb = sock_b.clone();
        let (a_x_pub, a_eph_pub_b, a_sign) = (a.x_pub, a_eph_pub.to_bytes(), a.signing.clone());
        let (b_x_pub, b_eph_pub_b, b_sign) = (b.x_pub, b_eph_pub.to_bytes(), b.signing.clone());

        let ha = tokio::spawn(async move {
            initial_handshake(
                &a_x_pub,
                &a_eph_priv,
                &a_eph_pub_b,
                &a_view_b,
                &a_sign,
                &sa,
                addr_b,
            )
            .await
        });
        let hb = tokio::spawn(async move {
            initial_handshake(
                &b_x_pub,
                &b_eph_priv,
                &b_eph_pub_b,
                &b_view_a,
                &b_sign,
                &sb,
                addr_a,
            )
            .await
        });
        let key_a = ha.await.unwrap().expect("A handshake");
        let key_b = hb.await.unwrap().expect("B handshake");
        assert_eq!(key_a, key_b, "both peers derive the same session key");

        let a_first = am_i_first(a.x_pub.as_bytes(), b.x_pub.as_bytes());
        let mut sess_a = start_session(
            Transport::Direct {
                socket: sock_a,
                remote: addr_b,
            },
            key_a,
            a.x_pub,
            a.signing,
            b.peerpub.clone(),
            a_first,
        );
        let mut sess_b = start_session(
            Transport::Direct {
                socket: sock_b,
                remote: addr_a,
            },
            key_b,
            b.x_pub,
            b.signing,
            a.peerpub.clone(),
            !a_first,
        );

        sess_a.outbound.send("hi from A".to_string()).await.unwrap();
        sess_b.outbound.send("hi from B".to_string()).await.unwrap();

        let got_b = tokio::time::timeout(Duration::from_secs(2), sess_b.events.recv())
            .await
            .expect("B receives in time");
        let got_a = tokio::time::timeout(Duration::from_secs(2), sess_a.events.recv())
            .await
            .expect("A receives in time");

        match got_b {
            Some(SessionEvent::Message { text, .. }) => assert_eq!(text, "hi from A"),
            other => panic!("B expected message, got {:?}", other),
        }
        match got_a {
            Some(SessionEvent::Message { text, .. }) => assert_eq!(text, "hi from B"),
            other => panic!("A expected message, got {:?}", other),
        }
    }

    #[test]
    fn am_i_first_is_deterministic_and_asymmetric() {
        let hi = [9u8; 32];
        let lo = [1u8; 32];
        assert!(am_i_first(&hi, &lo));
        assert!(!am_i_first(&lo, &hi));
    }

    #[tokio::test]
    async fn relay_session_roundtrip() {
        let a = ident();
        let b = ident();

        let key_a = relay_session_key(&b.peerpub.public, &a.x_priv);
        let key_b = relay_session_key(&a.peerpub.public, &b.x_priv);
        assert_eq!(key_a, key_b, "relay session key is symmetric");

        let (a_out_tx, mut a_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (a_in_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(100);
        let (b_out_tx, mut b_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (b_in_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(100);
        tokio::spawn(async move {
            while let Some(f) = a_out_rx.recv().await {
                let _ = b_in_tx.send(f).await;
            }
        });
        tokio::spawn(async move {
            while let Some(f) = b_out_rx.recv().await {
                let _ = a_in_tx.send(f).await;
            }
        });

        let a_first = am_i_first(a.x_pub.as_bytes(), b.x_pub.as_bytes());
        let sess_a = start_session(
            Transport::Relay {
                out: a_out_tx,
                inbound: a_in_rx,
            },
            key_a,
            a.x_pub,
            a.signing,
            b.peerpub.clone(),
            a_first,
        );
        let mut sess_b = start_session(
            Transport::Relay {
                out: b_out_tx,
                inbound: b_in_rx,
            },
            key_b,
            b.x_pub,
            b.signing,
            a.peerpub.clone(),
            !a_first,
        );

        sess_a
            .outbound
            .send("hi via relay".to_string())
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), sess_b.events.recv())
            .await
            .expect("B receives in time");
        match got {
            Some(SessionEvent::Message { text, .. }) => assert_eq!(text, "hi via relay"),
            other => panic!("B expected relayed message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stun_discover_returns_observed() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (_len, src) = server.recv_from(&mut buf).await.unwrap();
            let reply = StunReply {
                observed: "203.0.113.7:41000".to_string(),
            };
            let bytes = rmp_serde::to_vec(&reply).unwrap();
            let _ = server.send_to(&bytes, src).await;
        });

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let id = ident();
        let observed = stun_discover(
            &client_sock,
            &server_addr.to_string(),
            id.x_pub.to_bytes(),
            &id.signing,
        )
        .await;
        assert_eq!(observed, Some("203.0.113.7:41000".to_string()));
    }
}
