use crate::structs::*;
use crate::*;
use bytes::Bytes;
use chrono::Utc;
use futures_util::SinkExt;
use tokio::sync::mpsc::Sender;
use tokio_tungstenite::tungstenite::Message;

pub async fn ack_blob(blob_id: String, connection: &mut WsStream) -> Result<(), ClientErrors> {
    let ack_message = generate_ack_blob(blob_id);
    let wrapped = ClientToServer::new(ack_message, None);
    let bytes = rmp_serde::to_vec(&wrapped)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    connection
        .send(Message::Binary(Bytes::from(bytes)))
        .await
        .map_err(|e| ClientErrors::WriteFailed(e.to_string()))
}

pub async fn handle_blob(
    blob: BlobPayload,
    my_priv: &StaticSecret,
    events: &Sender<ServerEvent>,
) -> Result<(), ClientErrors> {
    match blob {
        BlobPayload::OfflineMessage {
            sender_pub_hash,
            timestamp,
            ciphertext,
            signature,
        } => {
            let now = Utc::now().timestamp();
            if (now - timestamp).abs() > 86400 * 30 {
                return Err(ClientErrors::ReplayDetected);
            }

            let peer_data = load_peer_data(&sender_pub_hash)
                .map_err(|e| ClientErrors::PeerLoadFailed(format!("{:?}", e)))?;

            let sig = Signature::from_slice(signature.as_slice())
                .map_err(|_| ClientErrors::InvalidSignature)?;

            let bytes_to_verify: Vec<u8> = [
                b"offline".as_slice(),
                ciphertext.as_slice(),
                &timestamp.to_le_bytes(),
            ]
            .concat();
            verify_challenge(peer_data.verifying, &bytes_to_verify, &sig)
                .map_err(|_| ClientErrors::InvalidSignature)?;

            let storage_key = load_storage_key(&peer_data.public, my_priv)
                .map_err(|_| ClientErrors::KeyDerivationFailed)?;
            let plaintext = decrypt_message_stored(&ciphertext, &storage_key)
                .map_err(|_| ClientErrors::DecryptionFailed)?;
            let sender_msg: crypto::Message = rmp_serde::from_slice(&plaintext)
                .map_err(|_| ClientErrors::InvalidMessageFormat)?;
            let msg = crypto::Message::from_parts(sender_msg.text, Author::Peer, timestamp);

            let db = load_peer_chat_file(&sender_pub_hash)
                .map_err(|e| ClientErrors::ChatStorageFailed(format!("{:?}", e)))?;
            insert_message_stored(msg, storage_key, db)
                .map_err(|e| ClientErrors::ChatStorageFailed(format!("{:?}", e)))?;

            crate::debug_log!(
                "offline message from {} stored in chat.db",
                hex::encode(sender_pub_hash)
            );
            let _ = events
                .send(ServerEvent::BlobStored {
                    sender_hash: sender_pub_hash,
                })
                .await;
        }
        BlobPayload::Purge {
            sender_pub_hash,
            signature,
            timestamp,
        } => {
            let now = Utc::now().timestamp();
            if (now - timestamp).abs() > 86400 * 30 {
                return Err(ClientErrors::ReplayDetected);
            }

            let peer_data =
                load_peer_data(&sender_pub_hash).map_err(|_| ClientErrors::UnknownPeer)?;
            let sig = Signature::from_slice(signature.as_slice())
                .map_err(|_| ClientErrors::InvalidSignature)?;
            let data = [b"purge".as_slice(), &timestamp.to_le_bytes()].concat();
            verify_challenge(peer_data.verifying, &data, &sig)
                .map_err(|_| ClientErrors::InvalidSignature)?;

            purge_peer_chat(&sender_pub_hash)
                .map_err(|e| ClientErrors::ChatStorageFailed(format!("{:?}", e)))?;
        }
    }
    Ok(())
}

pub async fn handle_message(
    msg: ServerToClient,
    privkey: &StaticSecret,
    events: &Sender<ServerEvent>,
) -> Result<Option<ClientToServer>, ClientErrors> {
    match msg.payload {
        ServerMessage::PendingBlob {
            blob_id,
            blob,
            timestamp: _,
        } => {
            crate::debug_log!(
                "pending blob {} ({} bytes) — decrypting",
                blob_id,
                blob.len()
            );
            let decrypted_blob = decrypt_blob(blob, privkey).map_err(|_| {
                crate::debug_log!("blob {blob_id} decrypt FAILED (envelope mismatch/wrong key)");
                ClientErrors::DecryptionFailed
            })?;
            let deserialized_blob: BlobPayload = rmp_serde::from_slice(&decrypted_blob)
                .map_err(|e| ClientErrors::DeserializationFailed(e.to_string()))?;
            handle_blob(deserialized_blob, privkey, events).await?;
            crate::debug_log!("blob {blob_id} handled + acked");
            let ack_message = generate_ack_blob(blob_id);
            Ok(Some(ClientToServer::new(ack_message, None)))
        }
        ServerMessage::PendingBlobsEnd => Ok(None),
        ServerMessage::PeerOnline { hash, ip_port } => {
            crate::debug_log!("peer online {} at {}", hex::encode(hash), ip_port);
            append_online_peer(hash, ip_port)?;
            Ok(None)
        }
        ServerMessage::PeerOffline { hash } => {
            remove_online_peer(hash)?;
            Ok(None)
        }
        ServerMessage::PunchHole {
            token,
            peer_hash,
            ip_port,
            punchtimestamp,
        } => {
            let _ = events
                .send(ServerEvent::PunchHole {
                    token,
                    peer_hash,
                    ip_port,
                    punchtimestamp,
                })
                .await;
            Ok(None)
        }
        ServerMessage::AuthOk { observed_address } => {
            get_or_set_my_address(Some(observed_address));
            Ok(None)
        }
        ServerMessage::AuthFailed { reason } => Err(ClientErrors::AuthFailed(reason)),
        ServerMessage::Error { reason } => Err(ClientErrors::ServerError(reason)),
        ServerMessage::RequestHolePunch { pub_key, token } => {
            let known = load_peer_data(&pub_key).is_ok();
            crate::debug_log!(
                "hole-punch request from {} — {}",
                hex::encode(pub_key),
                if known {
                    "ACCEPT (known peer)"
                } else {
                    "DENY (unknown peer)"
                }
            );
            let response = if known {
                ClientMessage::RequestAccepted { token }
            } else {
                ClientMessage::RequestDenied { token }
            };
            Ok(Some(ClientToServer::new(response, None)))
        }
        ServerMessage::RequestDenied {
            token: _,
            pub_key,
            reason,
        } => {
            let reason_string: String = match reason {
                RequestDeniedReason::PeerDeclined => "Peer declined your p2p request".into(),
                RequestDeniedReason::Timeout => "Request timed out try again later".into(),
            };
            let _ = events
                .send(ServerEvent::HolePunchDenied {
                    peer: pub_key,
                    reason: reason_string,
                })
                .await;
            Ok(None)
        }
        ServerMessage::RelayData {
            sender_hash,
            payload,
        } => {
            let _ = events
                .send(ServerEvent::RelayData {
                    sender_hash,
                    payload,
                })
                .await;
            Ok(None)
        }
    }
}

pub async fn server_initial_handshake(
    public: &PublicKey,
    signing: &SigningKey,
    privkey: &StaticSecret,
    conn: &mut WsStream,
    events: &Sender<ServerEvent>,
    udp_port: u16,
    announce_override: Option<String>,
) -> Result<String, ClientErrors> {
    let timestamp = Utc::now().timestamp();
    let auth_message = generate_authenticate_message(
        public.to_bytes(),
        signing.verifying_key().to_bytes(),
        signing,
        timestamp,
    )
    .map_err(|_| ClientErrors::KeyDerivationFailed)?;
    let auth_bytes = rmp_serde::to_vec(&auth_message)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    conn.send(Message::Binary(Bytes::from(auth_bytes)))
        .await
        .map_err(|e| ClientErrors::WriteFailed(e.to_string()))?;
    crate::debug_log!(
        "auth sent (x25519={}, verifying={})",
        hex::encode(public.to_bytes()),
        hex::encode(signing.verifying_key().to_bytes())
    );

    let response = receive_message(conn).await?;
    let observed_address = match response.payload {
        ServerMessage::AuthOk { observed_address } => {
            crate::debug_log!("auth OK — server sees us at {observed_address}");
            observed_address
        }
        ServerMessage::AuthFailed { reason } => {
            crate::debug_log!("auth FAILED: {reason}");
            return Err(ClientErrors::AuthFailed(reason));
        }
        other => {
            crate::debug_log!("unexpected handshake reply: {other:?}");
            return Err(ClientErrors::UnexpectedHandshakeMessage);
        }
    };
    let announce = announce_override.unwrap_or_else(|| match observed_address.rsplit_once(':') {
        Some((ip, _)) => format!("{ip}:{udp_port}"),
        None => observed_address.clone(),
    });
    crate::debug_log!("announcing presence as {announce}");
    get_or_set_my_address(Some(announce));
    let _ = events
        .send(ServerEvent::Authenticated {
            observed_address: observed_address.clone(),
        })
        .await;

    loop {
        let msg = receive_message(conn).await?;
        match msg.payload {
            ServerMessage::PendingBlobsEnd => break,
            ServerMessage::PendingBlob {
                blob_id,
                blob,
                timestamp: _,
            } => {
                let decrypted_blob =
                    decrypt_blob(blob, privkey).map_err(|_| ClientErrors::DecryptionFailed)?;
                let deserialized_blob: BlobPayload = rmp_serde::from_slice(&decrypted_blob)
                    .map_err(|e| ClientErrors::DeserializationFailed(e.to_string()))?;
                handle_blob(deserialized_blob, privkey, events).await?;
                ack_blob(blob_id, conn).await?;
            }
            ServerMessage::AuthFailed { reason } => return Err(ClientErrors::AuthFailed(reason)),
            ServerMessage::Error { reason } => return Err(ClientErrors::ServerError(reason)),
            _ => continue,
        }
    }

    let peers = load_peers().map_err(|e| ClientErrors::PeerLoadFailed(format!("{:?}", e)))?;
    let timestamp = Utc::now().timestamp();
    for peer in peers.iter() {
        let msg =
            generate_announce_message(privkey, &peer.public, timestamp, observed_address.clone())
                .map_err(|_| ClientErrors::KeyDerivationFailed)?;
        let wrapped = ClientToServer::new(msg, None);
        let bytes = rmp_serde::to_vec(&wrapped)
            .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
        conn.send(Message::Binary(Bytes::from(bytes)))
            .await
            .map_err(|e| ClientErrors::WriteFailed(e.to_string()))?;
    }

    Ok(observed_address)
}
