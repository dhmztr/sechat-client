use chrono::Utc;
use crypto::Message;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum ClientErrors {
    ConnectionError,
    BadPacket,
    DwarfPacket,
}

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
    pub fn new(payload: ClientMessage) -> Self {
        let timestamp = Utc::now().timestamp();
        ClientToServer { payload, timestamp }
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
    AckBlob {
        blob_id: String,
    },
    LookupPeer {
        token: [u8; 32],
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
        timestamp: u64,
    },
    PeerOnline {
        token: [u8; 32],
        ip_port: String,
    },
    PeerOffline {
        token: [u8; 32],
    },
    PeerFound {
        token: [u8; 32],
        ip_port: String,
    },
    PeerNotFound {
        token: [u8; 32],
    },
    Error {
        reason: String,
    },
    PendingBlobsEnd,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlobPayload {
    FriendRequest {
        sender_x25519_pub: [u8; 32],
        sender_ed25519_verifying: [u8; 32],
    },
    FriendAccept {
        sender_x25519_pub: [u8; 32],
        sender_ed25519_verifying: [u8; 32],
    },
    OfflineMessage {
        sender_x25519_pub: [u8; 32],
        timestamp: u64,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
    },
    Purge {
        sender_x25519_pub: [u8; 32],
        new_x25519_pub: [u8; 32],
        new_ed25519_verifying: [u8; 32],
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
        counter: u64,
        ciphertext: Vec<u8>,
    },
    SyncRequest {
        last_timestamp: u64,
    },
    SyncResponse {
        messages: Vec<Message>,
    },
    Heartbeat,
    Disconnect,
}
