use crypto::*;
use ed25519_dalek::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
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
    paylaod: ServerMessage,
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

async fn generate_authenticate_message(
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
