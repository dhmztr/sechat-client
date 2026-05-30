use crypto::*;
use ed25519_dalek::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use x25519_dalek::*;
mod structs;
use chrono::Utc;
use structs::*;
pub enum Payload {
    OfflineMessage,
    Announce,
}
pub enum ClientErrors {
    ConnectionError,
    DwarfPacket,
}
#[derive(Serialize)]
pub struct ClientToServer {
    payload: ClientMessage,
    timestamp: i64,
}
#[derive(Deserialize)]
pub struct ServerToClient {
    payload: ServerMessage,
    timestamp: i64,
}

impl ClientToServer {
    fn new(payload: ClientMessage) -> Self {
        let timestamp = Utc::now().timestamp();
        ClientToServer { payload, timestamp }
    }
}
type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn connect_to_server(server_address: String) -> Result<WsStream, ClientErrors> {
    let url = format!("wss://{}/ws", server_address);
    let (mut ws, _) = connect_async(url)
        .await
        .map_err(|_| ClientErrors::ConnectionError)?;
    Ok(ws)
}
async fn server_inital_handshake(
    public: &PublicKey,
    singing: &SigningKey,
    privkey: &StaticSecret,
    peers: Vec<&PublicKey>,
    server_address: String,
) -> Result<(), ClientErrors> {
    let connection = connect_to_server(server_address).await?;
    let auth_message = ClientToServer::new(generate_authenticate_message(public.to_bytes(), singing)?);
    connection
        .send(serde_json::to_string(&auth_message).unwrap().into())
        .await
        .map_err(|_| ClientErrors::ConnectionError)?;
    let response = connection
        .next()
        .await
        .ok_or(ClientErrors::ConnectionError)?
        .map_err(|_| ClientErrors::ConnectionError)?;
    let server_message = parse_server_message(&response.to_string())?;
    match server_message.payload {
        ServerMessage::AuthFailed { reason } => {
            eprintln!("Authentication failed: {}", reason);
            Err(ClientErrors::ConnectionError)
        }
        ServerMessage::PendingBlob { blob_id, blob, timestamp }
        ServerMessage::AuthOk { ip_port} => {
            peers.iter().for_each(|peer_pub| {
                let announce_message =
                    generate_announce_message(privkey, peer_pub, Utc::now().timestamp() as u64, ip_port.clone());
                    connection
    

    );
}
fn generate_authenticate_message(
    public: [u8; 32],
    singing: &SigningKey,
) -> Result<ClientToServer, CryptoErrors> {
    let (data, _) = sign_challenge(singing);
    let payload = ClientMessage::Auth {
        pub_key: public,
        signature: data.to_vec(),
    };
    Ok(ClientToServer::new(payload))
}
fn generate_announce_message(
    privkey: &StaticSecret,
    peer_pub: &PublicKey,
    timestamp: u64,
    ip_port: String,
) -> Result<ClientMessage, CryptoErrors> {
    let token = presence_token(privkey, peer_pub, timestamp)?;
    Ok(ClientMessage::Announce { token, ip_port })
}

fn generate_unannounce_message(
    privkey: &StaticSecret,
    peer_pub: &PublicKey,
    timestamp: u64,
) -> Result<ClientMessage, CryptoErrors> {
    let token = presence_token(privkey, peer_pub, timestamp)?;
    Ok(ClientMessage::Unannounce { token })
}

fn generate_blob(peer_pub: &PublicKey, message: Vec<u8>) -> Result<ClientMessage, CryptoErrors> {
    let hash: [u8; 32] = generate_peer_hash(peer_pub);
    Ok(ClientMessage::SendBlob {
        recipient_hash: hash,
        blob: message,
    })
}
fn generate_peer_hash(peer_pub: &PublicKey) -> [u8; 32] {
    Sha256::digest(peer_pub.as_bytes()).into()
}

pub fn generate_peer_lookup(peer_pub: &PublicKey) -> ClientMessage {
    ClientMessage::LookupPeer {
        token: generate_peer_hash(peer_pub),
    }
}
pub fn generate_ack_blob(blob_id: String) -> ClientMessage {
    ClientMessage::AckBlob { blob_id }
}
pub fn parse_server_message(msg: &str) -> Result<ServerToClient, ClientErrors> {
    serde_json::from_str(msg).map_err(|_| ClientErrors::DwarfPacket)
}
