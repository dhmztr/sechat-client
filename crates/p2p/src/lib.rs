use chrono::Utc;
use crypto::*;
use ed25519_dalek::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::iter::zip;
use std::{ops::Deref, sync::Arc};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tokio::{net::UdpSocket, *};
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
    SocketError,
    SendError,
    RecvError,
    Timeout,
    Success(Option<Arc<UdpSocket>>),
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
    fn verify(&self, expected_sender: &[u8; 32]) -> bool {
        if &self.sender.to_bytes() != expected_sender {
            return false;
        }
        let hash: [u8; 32] = Sha256::digest(&self.sender).into();
        let peerverif = match load_peer_data(&hash) {
            Ok(data) => data,
            _ => return false,
        };
        let payload_bytes = match self.payload {
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
        let data_to_verify = [
            self.sender.to_bytes().as_slice(),
            self.timestamp.to_le_bytes().as_slice(),
            &payload_bytes.as_slice(),
        ]
        .concat();
        let signature = match Signature::from_slice(&self.signature.as_slice()) {
            Ok(sig) => sig,
            _ => return false,
        };
        verify_challenge(peerverif.verifying, &data_to_verify, &signature).is_ok()
    }
}
pub async fn punch_hole(
    timestamp: u64,
    mypubkey: PublicKey,
    remote_pubkey: PublicKey,
    myaddr: &str,
    remote_addr: &str,
) -> PunchHoleResult {
    let socket = UdpSocket::bind(myaddr)
        .await
        .map_err(|_| PunchHoleResult::SocketError)
        .unwrap();
    let arc_socket = Arc::new(socket);
    let write_socket = arc_socket.clone();
    let read_socket = arc_socket.clone();
    let remote_addr_send = remote_addr.to_string().clone();
    let send_task = tokio::spawn(async move {
        let ping = Ping {
            pubkey: mypubkey.to_bytes(),
            timestamp,
        };
        let data = rmp_serde::to_vec(&ping)
            .map_err(|_| PunchHoleResult::SendError)
            .unwrap();
        for _ in 0..20 {
            write_socket
                .send_to(&data, &remote_addr_send)
                .await
                .map_err(|_| PunchHoleResult::SendError)
                .unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    });
    let recv_task: JoinHandle<PunchHoleResult> = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match timeout(Duration::from_secs(10), read_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    let ping: Ping = rmp_serde::from_slice(&buf[..len])
                        .map_err(|_| PunchHoleResult::RecvError)
                        .unwrap();
                    if ping.pubkey == remote_pubkey.to_bytes() && ping.timestamp == timestamp {
                        return PunchHoleResult::Success(None);
                    }
                }
                Ok(Err(_)) => return PunchHoleResult::RecvError,

                Err(_) => return PunchHoleResult::Timeout,
            }
        }
    });
    recv_task
        .await
        .map_err(|_| PunchHoleResult::RecvError)
        .unwrap();
    send_task.abort();
    PunchHoleResult::Success(Some(arc_socket))
}

pub fn am_i_first(mypubkey: &[u8; 32], remote_pubkey: &[u8; 32]) -> bool {
    mypubkey > remote_pubkey
}

pub async fn initial_handshake(
    my_pubkey: &PublicKey,
    myephermal_priv: &StaticSecret,
    myephermal_pub: &[u8; 32],
    remote_pubkey: &[u8; 32],
    my_signing: &SigningKey,
    socket: UdpSocket,
) -> Result<[u8; 32], P2PError> {
    let mut buf: [u8; 1024] = [0u8; 1024];
    let amount: usize;
    if am_i_first(my_pubkey.as_bytes(), remote_pubkey) {
        let firstpayload = P2PMessage::Init {
            ephermal: *myephermal_pub,
        };
        let firstmsg = PeerMessage::new(firstpayload, my_pubkey.into(), my_signing);
        let parsed = rmp_serde::to_vec(&firstmsg).map_err(|_| P2PError::SerializationFailed)?;
        socket
            .send(parsed.as_slice())
            .await
            .map_err(|_| P2PError::CommunicationError)?;

        amount = timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| P2PError::Timeout)?
            .map_err(|_| P2PError::CommunicationError)?;
    } else {
        amount = timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| P2PError::Timeout)?
            .map_err(|_| P2PError::CommunicationError)?;

        let firstpayload = P2PMessage::Init {
            ephermal: *myephermal_pub,
        };
        let firstmsg = PeerMessage::new(firstpayload, my_pubkey.into(), my_signing);
        let parsed = rmp_serde::to_vec(&firstmsg).map_err(|_| P2PError::SerializationFailed)?;
        socket
            .send(parsed.as_slice())
            .await
            .map_err(|_| P2PError::CommunicationError)?;
    }
    let msgbytes = &buf[0..amount];
    let peerinit: PeerMessage =
        rmp_serde::from_slice(msgbytes).map_err(|_| P2PError::DeserializationFailed)?;
    if peerinit.verify(remote_pubkey) {
        return Err(P2PError::CryptographicError);
    }
    match peerinit.payload {
        P2PMessage::Init { ephermal } => {
            let peerephermalpub = PublicKey::from(ephermal);

            derive_session_key(myephermal_priv, &peerephermalpub)
                .map_err(|_| P2PError::CryptographicError)
        }
        _ => return Err(P2PError::CommunicationError),
    }
}

pub async fn handle_message(
    sender: mpsc::Sender<P2PMessage>,
    recv: mpsc::Receiver<P2PMessage>,
) -> Result<(), P2PError> {
    while let Some(msg) = recv.recv().await {
        match msg {
            P2PMessage::ChatMessage {
                counter,
                message_bytes,
            } => {}
        }
    }
    Ok(())
}

pub async fn fetch_
