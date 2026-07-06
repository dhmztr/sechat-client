use bytes::Bytes;
use crypto::*;
use ed25519_dalek::*;
use futures::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use handlers::*;
use sha2::{Digest, Sha256};
use std::sync::RwLock;
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, Receiver, Sender},
    time::interval,
};
mod generators;
use generators::*;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use x25519_dalek::*;

mod handlers;
mod structs;

use chrono::Utc;
use structs::*;

#[derive(PartialEq, Clone)]
pub struct OnlinePeer {
    pub keys: PeerPublic,
    pub address: String,
}

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

static MY_ADDRESS: RwLock<Option<String>> = RwLock::new(None);
static PEERS: RwLock<Vec<OnlinePeer>> = RwLock::new(vec![]);

pub fn load_online_peers() -> Result<Vec<OnlinePeer>, ClientErrors> {
    let peers = PEERS
        .read()
        .map_err(|e| ClientErrors::PeerLoadFailed(format!("lock poisoned: {}", e)))?;
    Ok(peers.clone())
}

pub fn append_online_peer(hash: [u8; 32], ip_port: String) -> Result<(), ClientErrors> {
    let mut peers = PEERS
        .write()
        .map_err(|e| ClientErrors::PeerSaveFailed(format!("lock poisoned: {}", e)))?;
    let peer_data = load_peer_data(&hash).map_err(|_| ClientErrors::UnknownPeer)?;
    let insertable = OnlinePeer {
        keys: peer_data,
        address: ip_port,
    };
    if !peers.contains(&insertable) {
        peers.push(insertable);
    }
    Ok(())
}

pub fn remove_online_peer(hash: [u8; 32]) -> Result<(), ClientErrors> {
    let mut peers = PEERS
        .write()
        .map_err(|e| ClientErrors::PeerSaveFailed(format!("lock poisoned: {}", e)))?;
    peers.retain(|peer| generate_peer_hash(&peer.keys.public) != hash);
    Ok(())
}

pub fn get_or_set_my_address(new_address: Option<String>) -> Option<String> {
    let mut address = MY_ADDRESS.write().ok()?;
    if let Some(addr) = new_address {
        *address = Some(addr.clone());
        Some(addr)
    } else {
        address.clone()
    }
}

async fn connect_to_server(server_address: String) -> Result<WsStream, ClientErrors> {
    let url = format!("wss://{}/ws", server_address);
    let (ws, _) = connect_async(url)
        .await
        .map_err(|e| ClientErrors::ConnectionFailed(e.to_string()))?;
    Ok(ws)
}

pub async fn run_client(
    public: PublicKey,
    signing: SigningKey,
    privkey: StaticSecret,
    server_address: String,
) -> Result<(), ClientErrors> {
    let mut connection = connect_to_server(server_address.clone()).await?;

    server_initial_handshake(&public, &signing, &privkey, &mut connection).await?;

    let (write, read) = connection.split();

    let (out_tx, out_rx) = mpsc::channel::<ClientToServer>(100);
    let (in_tx, in_rx) = mpsc::channel::<ServerToClient>(100);

    let write_handle = tokio::spawn(write_loop(out_rx, write));
    let read_handle = tokio::spawn(read_loop(read, in_tx));

    let privkey_for_presence = privkey.clone();
    let out_tx_for_presence = out_tx.clone();
    let presence_handle = tokio::spawn(presence_refresh_loop(
        out_tx_for_presence,
        privkey_for_presence,
    ));

    let privkey_for_dispatch = privkey.clone();
    let dispatch_handle = tokio::spawn(main_dispatch_loop(in_rx, out_tx, privkey_for_dispatch));

    tokio::select! {
        _ = write_handle => eprintln!("write_loop ended"),
        _ = read_handle => eprintln!("read_loop ended"),
        _ = presence_handle => eprintln!("presence_refresh ended"),
        _ = dispatch_handle => eprintln!("dispatch ended"),
    }

    Ok(())
}

pub async fn main_dispatch_loop(
    mut in_rx: Receiver<ServerToClient>,
    out_tx: Sender<ClientToServer>,
    privkey: StaticSecret,
) {
    while let Some(msg) = in_rx.recv().await {
        match handle_message(msg, &privkey).await {
            Ok(Some(response)) => {
                if out_tx.send(response).await.is_err() {
                    eprintln!("{}", ClientErrors::ChannelClosed);
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("handle_message error: {}", e),
        }
    }
}

pub async fn presence_refresh_loop(out_tx: Sender<ClientToServer>, privkey: StaticSecret) {
    let mut ticker = interval(Duration::from_secs(15));
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let address = match get_or_set_my_address(None) {
            Some(a) => a,
            None => continue,
        };

        let peers = match load_peers() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("presence: load_peers failed: {:?}", e);
                continue;
            }
        };

        let timestamp = Utc::now().timestamp();

        for peer in peers.iter() {
            let msg =
                match generate_announce_message(&privkey, &peer.public, timestamp, address.clone())
                {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("presence: generate_announce failed: {:?}", e);
                        continue;
                    }
                };
            if out_tx.send(ClientToServer::new(msg, None)).await.is_err() {
                eprintln!("presence: {}", ClientErrors::ChannelClosed);
                return;
            }
        }
    }
}

pub async fn write_loop(
    mut reader: Receiver<ClientToServer>,
    mut writer: SplitSink<WsStream, Message>,
) {
    while let Some(msg) = reader.recv().await {
        let bytes = match rmp_serde::to_vec(&msg) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}", ClientErrors::SerializationFailed(e.to_string()));
                continue;
            }
        };
        if let Err(e) = writer.send(Message::Binary(Bytes::from(bytes))).await {
            eprintln!("{}", ClientErrors::WriteFailed(e.to_string()));
            break;
        }
    }
}

pub async fn read_loop(mut reader: SplitStream<WsStream>, writer: Sender<ServerToClient>) {
    while let Some(message) = reader.next().await {
        match message {
            Ok(Message::Binary(data)) => match parse_server_message(&data) {
                Ok(parsed_msg) => {
                    if writer.send(parsed_msg).await.is_err() {
                        eprintln!("{}", ClientErrors::ChannelClosed);
                        break;
                    }
                }
                Err(e) => eprintln!("read_loop: {}", e),
            },
            Ok(Message::Close(_)) => {
                eprintln!("{}", ClientErrors::ConnectionClosed);
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}", ClientErrors::ReadFailed(e.to_string()));
                break;
            }
        }
    }
}

pub async fn receive_message(connection: &mut WsStream) -> Result<ServerToClient, ClientErrors> {
    loop {
        let response = connection
            .next()
            .await
            .ok_or(ClientErrors::ConnectionClosed)?
            .map_err(|e| ClientErrors::ReadFailed(e.to_string()))?;

        match response {
            Message::Binary(data) => return parse_server_message(&data),
            Message::Close(_) => return Err(ClientErrors::ConnectionClosed),
            _ => continue,
        }
    }
}

pub fn parse_server_message(msg: &[u8]) -> Result<ServerToClient, ClientErrors> {
    rmp_serde::from_slice(msg).map_err(|e| ClientErrors::DeserializationFailed(e.to_string()))
}
