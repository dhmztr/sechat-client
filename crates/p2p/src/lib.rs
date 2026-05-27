use chacha20poly1305::Key;
use chrono::{DateTime, Utc};
use crypto::*;
use serde::{Deserialize, Serialize};
use tokio::net::{UdpSocket, unix::SocketAddr};
use x25519_dalek::PublicKey;
#[derive(Serialize, Deserialize)]
struct Ping {
    timestamp: i64,
}
enum SendErrors {}
struct Data {
    sender: PublicKey,
    payload: Payload,
}
enum MessagePayload {
    Ping(Ping),
    Message(Msg),
}
struct Msg {
    bytes: Vec<u8>,
}
impl Msg {
    fn new(plaintext: String, key: Key, counter: u64) -> Self {
        let bytes = encrypt_message(plaintext, key, counter);
        Msg { bytes }
    }
    fn decrypt(&self, key: Key, counter: u64) -> Option<String> {
        if let Ok(plaintext) = crypto::decrypt_message(self.bytes.to_vec(), key, counter) {
            Some(plaintext)
        } else {
            None
        }
    }
}
impl Ping {
    fn new(key: PublicKey) -> Self {
        let stamp = Utc::now();
        Ping {
            timestamp: stamp.timestamp(),
        }
    }
}

async fn send_data(socket: UdpSocket, key: PublicKey, data: Data) -> Result<(), SendErrors> {}

async fn create_ping() {}

async fn create_message() {}

async fn connect_to_peer() {}

async fn keep_connection() {}

async fn receive_data() {}
