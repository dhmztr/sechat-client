use crate::structs::*;
use crate::*;
use bytes::Bytes;
use chrono::Utc;
use crypto::*;
use ed25519_dalek::*;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::*;

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

pub async fn handle_blob(blob: BlobPayload) -> Result<(), ClientErrors> {
    match blob {
        BlobPayload::OfflineMessage {
            sender_pub_hash,
            timestamp,
            ciphertext,
            signature,
        } => {
            // weryfikacja timestamp - odrzuć stare wiadomości (replay protection)
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

            let stored_chat = load_peer_chat_file(&sender_pub_hash)
                .map_err(|e| ClientErrors::ChatStorageFailed(format!("{:?}", e)))?;
            insert_blob_to_chat(ciphertext, &stored_chat)
                .map_err(|e| ClientErrors::ChatStorageFailed(format!("{:?}", e)))?;
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
) -> Result<Option<ClientToServer>, ClientErrors> {
    match msg.payload {
        ServerMessage::PendingBlob {
            blob_id,
            blob,
            timestamp: _,
        } => {
            let decrypted_blob =
                decrypt_blob(blob, privkey).map_err(|_| ClientErrors::DecryptionFailed)?;
            let deserialized_blob: BlobPayload = rmp_serde::from_slice(&decrypted_blob)
                .map_err(|e| ClientErrors::DeserializationFailed(e.to_string()))?;
            handle_blob(deserialized_blob).await?;
            let ack_message = generate_ack_blob(blob_id);
            Ok(Some(ClientToServer::new(ack_message, None)))
        }
        ServerMessage::PendingBlobsEnd => Ok(None),
        ServerMessage::PeerOnline { hash, ip_port } => {
            append_online_peer(hash, ip_port)?;
            Ok(None)
        }
        ServerMessage::PeerOffline { hash } => {
            remove_online_peer(hash)?;
            Ok(None)
        }
        ServerMessage::PunchHole {
            token,
            ip_port,
            punchtimestamp,
        } => {
            tokio::spawn(async move {
                if let Err(e) = punch_hole(token, ip_port, punchtimestamp) {
                    eprintln!("punch_hole failed: {:?}", e);
                }
            });
            Ok(None)
        }
        ServerMessage::AuthOk { observed_address } => {
            get_or_set_my_address(Some(observed_address));
            Ok(None)
        }
        ServerMessage::AuthFailed { reason } => Err(ClientErrors::AuthFailed(reason)),
        ServerMessage::Error { reason } => Err(ClientErrors::ServerError(reason)),
        ServerMessage::RequestHolePunch { pub_key, token } => {
            let response = if check_if_connection_wanted(pub_key) == true {
                ClientMessage::RequestAccepted { token }
            } else {
                ClientMessage::RequestDenied { token }
            };
            Ok(Some(ClientToServer::new(response, None)))
        }
        ServerMessage::RequestDenied {
            token,
            pub_key,
            reason,
        } => {
            let reason_string: String = match reason {
                RequestDeniedReason::PeerDeclined => "Peer declined your p2p request".into(),
                RequestDeniedReason::Timeout => "Request timed out try again later".into(),
            };
            propagate_deny_to_client(pub_key, reason_string);
            Ok(None)
        }
    }
}

pub async fn server_initial_handshake(
    public: &PublicKey,
    signing: &SigningKey,
    privkey: &StaticSecret,
    conn: &mut WsStream,
) -> Result<String, ClientErrors> {
    let timestamp = Utc::now().timestamp();
    let auth_message = generate_authenticate_message(public.to_bytes(), signing, timestamp)
        .map_err(|_| ClientErrors::KeyDerivationFailed)?;
    let auth_bytes = rmp_serde::to_vec(&auth_message)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    conn.send(Message::Binary(Bytes::from(auth_bytes)))
        .await
        .map_err(|e| ClientErrors::WriteFailed(e.to_string()))?;

    let response = receive_message(conn).await?;
    let observed_address = match response.payload {
        ServerMessage::AuthOk { observed_address } => observed_address,
        ServerMessage::AuthFailed { reason } => return Err(ClientErrors::AuthFailed(reason)),
        _ => return Err(ClientErrors::UnexpectedHandshakeMessage),
    };
    get_or_set_my_address(Some(observed_address.clone()));

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
                handle_blob(deserialized_blob).await?;
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
