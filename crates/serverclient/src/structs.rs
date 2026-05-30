use serde::{Deserialize, Serialize};
#[derive(Serialize)]
pub enum ClientMessage {
    Auth {
        pub_key: [u8; 32], // Ed25519 verifying key
        signature: Vec<u8>,
    },

    Announce {
        token: [u8; 32], // HMAC(presence_key, ts/15*15)
        ip_port: String, // gdzie hole punch
    },

    Unannounce {
        token: [u8; 32],
    },

    SendBlob {
        recipient_hash: [u8; 32], // sha256(odbiorca_pub)
        blob: Vec<u8>,            // zaszyfrowana treść
    },

    AckBlob {
        blob_id: String,
    },

    LookupPeer {
        token: [u8; 32],
    },
}

#[derive(Serialize, Deserialize)]
pub enum ServerMessage {
    AuthOk {
        ip_port: String,
    }
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
}
