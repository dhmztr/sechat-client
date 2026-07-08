use chrono::Utc;
use crypto::Message;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug)]
pub enum ClientErrors {
    ConnectionFailed(String),
    ConnectionClosed,
    ConnectionTimeout,
    WriteFailed(String),
    ReadFailed(String),

    SerializationFailed(String),
    DeserializationFailed(String),
    InvalidMessageFormat,

    AuthFailed(String),
    AuthTimeout,
    UnexpectedHandshakeMessage,

    InvalidSignature,
    InvalidTimestamp,
    ReplayDetected,
    UnknownPeer,
    InvalidPublicKey,

    DecryptionFailed,
    EncryptionFailed,
    KeyDerivationFailed,

    PeerLoadFailed(String),
    PeerSaveFailed(String),
    ChatStorageFailed(String),

    ChannelClosed,
    ServerError(String),
}

impl fmt::Display for ClientErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientErrors::ConnectionFailed(s) => write!(f, "connection failed: {}", s),
            ClientErrors::ConnectionClosed => write!(f, "connection closed"),
            ClientErrors::ConnectionTimeout => write!(f, "connection timeout"),
            ClientErrors::WriteFailed(s) => write!(f, "write failed: {}", s),
            ClientErrors::ReadFailed(s) => write!(f, "read failed: {}", s),
            ClientErrors::SerializationFailed(s) => write!(f, "serialization failed: {}", s),
            ClientErrors::DeserializationFailed(s) => write!(f, "deserialization failed: {}", s),
            ClientErrors::InvalidMessageFormat => write!(f, "invalid message format"),
            ClientErrors::AuthFailed(s) => write!(f, "auth failed: {}", s),
            ClientErrors::AuthTimeout => write!(f, "auth timeout"),
            ClientErrors::UnexpectedHandshakeMessage => write!(f, "unexpected handshake message"),
            ClientErrors::InvalidSignature => write!(f, "invalid signature"),
            ClientErrors::InvalidTimestamp => write!(f, "invalid timestamp"),
            ClientErrors::ReplayDetected => write!(f, "replay attack detected"),
            ClientErrors::UnknownPeer => write!(f, "unknown peer"),
            ClientErrors::InvalidPublicKey => write!(f, "invalid public key"),
            ClientErrors::DecryptionFailed => write!(f, "decryption failed"),
            ClientErrors::EncryptionFailed => write!(f, "encryption failed"),
            ClientErrors::KeyDerivationFailed => write!(f, "key derivation failed"),
            ClientErrors::PeerLoadFailed(s) => write!(f, "peer load failed: {}", s),
            ClientErrors::PeerSaveFailed(s) => write!(f, "peer save failed: {}", s),
            ClientErrors::ChatStorageFailed(s) => write!(f, "chat storage failed: {}", s),
            ClientErrors::ChannelClosed => write!(f, "internal channel closed"),
            ClientErrors::ServerError(s) => write!(f, "server reported error: {}", s),
        }
    }
}

impl std::error::Error for ClientErrors {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientToServer {
    pub payload: ClientMessage,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerToClient {
    pub payload: ServerMessage,
    pub timestamp: i64,
}

impl ClientToServer {
    pub fn new(payload: ClientMessage, timestamp: Option<i64>) -> Self {
        ClientToServer {
            payload,
            timestamp: timestamp.unwrap_or(Utc::now().timestamp()),
        }
    }
}

impl ServerToClient {
    pub fn new(payload: ServerMessage) -> Self {
        let timestamp = Utc::now().timestamp();
        ServerToClient { payload, timestamp }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientMessage {
    Auth {
        pub_key: [u8; 32],
        verif: [u8; 32],
        signature: Vec<u8>,
    },
    Announce {
        token: [u8; 32],
        ip_port: String,
    },
    Unannounce {
        token: [u8; 32],
    },
    SendBlob {
        recipient_hash: [u8; 32],
        blob: Vec<u8>,
    },
    Purge {
        hash_pubkey: [u8; 32],
    },
    AckBlob {
        blob_id: String,
    },
    LookupPeer {
        token: [u8; 32],
    },
    RequestHolePunch {
        token: [u8; 32],
    },
    RequestDenied {
        token: [u8; 32],
    },
    RequestAccepted {
        token: [u8; 32],
    },
    RelayData {
        recipient_hash: [u8; 32],
        payload: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ServerMessage {
    AuthOk {
        observed_address: String,
    },
    AuthFailed {
        reason: String,
    },
    PendingBlob {
        blob_id: String,
        blob: Vec<u8>,
        timestamp: i64,
    },
    PeerOnline {
        hash: [u8; 32],
        ip_port: String,
    },
    PeerOffline {
        hash: [u8; 32],
    },
    PunchHole {
        token: [u8; 32],
        ip_port: String,
        punchtimestamp: i64,
    },
    Error {
        reason: String,
    },
    PendingBlobsEnd,
    RequestHolePunch {
        pub_key: [u8; 32],
        token: [u8; 32],
    },
    RequestDenied {
        token: [u8; 32],
        pub_key: [u8; 32],
        reason: RequestDeniedReason,
    },
    RelayData {
        sender_hash: [u8; 32],
        payload: Vec<u8>,
    },
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum RequestDeniedReason {
    PeerDeclined,
    Timeout,
}

#[derive(Debug, Clone)]
pub enum ServerEvent {
    Authenticated {
        observed_address: String,
    },
    PeerOnline {
        hash: [u8; 32],
        ip_port: String,
    },
    PeerOffline {
        hash: [u8; 32],
    },
    PunchHole {
        token: [u8; 32],
        ip_port: String,
        punchtimestamp: i64,
    },
    HolePunchDenied {
        peer: [u8; 32],
        reason: String,
    },
    BlobStored {
        sender_hash: [u8; 32],
    },
    RelayData {
        sender_hash: [u8; 32],
        payload: Vec<u8>,
    },
    Disconnected,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlobPayload {
    OfflineMessage {
        sender_pub_hash: [u8; 32],
        timestamp: i64,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
    },
    Purge {
        sender_pub_hash: [u8; 32],
        signature: Vec<u8>,
        timestamp: i64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    SessionInit {
        ephemeral_pub: [u8; 32],
        signature: Vec<u8>,
    },
    Challenge {
        nonce: [u8; 32],
    },
    ChallengeResponse {
        signature: Vec<u8>,
    },
    ChatMessage {
        counter: i64,
        ciphertext: Vec<u8>,
    },
    SyncRequest {
        last_timestamp: i64,
    },
    SyncResponse {
        messages: Vec<Message>,
    },
    Heartbeat,
    Disconnect,
}
