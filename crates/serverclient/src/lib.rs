use crypto::*;
use ed25519_dalek::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use x25519_dalek::*;
mod structs;
use chrono::Utc;
use structs::*;
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
    let auth_message =
        ClientToServer::new(generate_authenticate_message(public.to_bytes(), singing)?);
    connection
        .send(serde_json::to_string(&auth_message).unwrap().into())
        .await
        .map_err(|_| ClientErrors::ConnectionError)?;
    let response = receive_message(&mut connection).await?;
    match server_message.payload {
        ServerMessage::AuthOk { observed_address } => loop {
            let msg = receive_message(&mut connection).await?;
            match msg.payload {
                ServerMessage::PendingBlob {
                    blob_id,
                    blob,
                    timestamp,
                } => {
                    let decrypted_blob =
                        decrypt_blob(blob, &privkey).map_err(|_| ClientErrors::DwarfPacket)?;
                    let deserialized_blob: BlobPayload = rmp_serde::from_slice(&decrypted_blob)
                        .map_err(|_| ClientErrors::DwarfPacket)?;
                    handle_blob(deserialized_blob).await?;
                    ack_blob(blob_id, &mut connection).await?;
                }
            }
        },
    }
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
pub async fn receive_message(
    &mut connection: &mut WsStream,
) -> Result<ServerToClient, ClientErrors> {
    let response = connection
        .next()
        .await
        .ok_or(ClientErrors::ConnectionError)?
        .map_err(|_| ClientErrors::ConnectionError)?;
    parse_server_message(&response.to_string())
}
pub async fn ack_blob(blob_id: String, connection: &mut WsStream) -> Result<(), ClientErrors> {
    let ack_message = generate_ack_blob(blob_id);
    connection
        .send(
            serde_json::to_string(&ClientToServer::new(ack_message))
                .unwrap()
                .into(),
        )
        .await
        .map_err(|_| ClientErrors::ConnectionError)
}
pub async fn handle_blob(blob: BlobPayload) -> Result<(), ClientErrors> {
    match blob {
        BlobPayload::OfflineMessage {
            sender_x25519_pub,
            timestamp,
            ciphertext,
            signature,
        } => {
            let public_peer = PublicKey::from(sender_x25519_pub);
            if !load_peers()
                .map_err(|_| ClientErrors::DwarfPacket)?
                .contains(&public_peer)
            {
                return Err(ClientErrors::BadPacket);
            };
            let stored_chat =
                load_peer_chat_file(&public_peer).map_err(|_| ClientErrors::DwarfPacket)?;
            insert_blob_to_chat(ciphertext, &stored_chat);
        }
    }
    Ok(())
}
