use crate::*;

pub fn generate_authenticate_message(
    public: [u8; 32],
    signing: &SigningKey,
    timestamp: i64,
) -> Result<ClientToServer, CryptoErrors> {
    let data_to_sign = [public.as_slice(), &timestamp.to_le_bytes()].concat();
    let data = sign_challenge(signing, &data_to_sign);
    let payload = ClientMessage::Auth {
        pub_key: public,
        signature: data.to_vec(),
    };
    Ok(ClientToServer::new(payload, Some(timestamp)))
}

pub fn generate_announce_message(
    privkey: &StaticSecret,
    peer_pub: &PublicKey,
    timestamp: i64,
    ip_port: String,
) -> Result<ClientMessage, CryptoErrors> {
    let token = presence_token(privkey, peer_pub, timestamp)?;
    Ok(ClientMessage::Announce { token, ip_port })
}

pub fn generate_unannounce_message(
    privkey: &StaticSecret,
    peer_pub: &PublicKey,
    timestamp: i64,
) -> Result<ClientMessage, CryptoErrors> {
    let token = presence_token(privkey, peer_pub, timestamp)?;
    Ok(ClientMessage::Unannounce { token })
}

pub fn generate_blob(
    peer_pub: &PublicKey,
    message: Vec<u8>,
) -> Result<ClientMessage, CryptoErrors> {
    let hash: [u8; 32] = generate_peer_hash(peer_pub);
    Ok(ClientMessage::SendBlob {
        recipient_hash: hash,
        blob: message,
    })
}

pub fn generate_purge_message(
    peerkey: &PublicKey,
    sign: &SigningKey,
) -> Result<ClientToServer, ClientErrors> {
    let timestamp = Utc::now().timestamp();
    let bytes_to_sign = [b"purge".as_slice(), &timestamp.to_le_bytes()].concat();

    let signed = sign_challenge(sign, bytes_to_sign.as_slice());
    let purge_payload = BlobPayload::Purge {
        sender_pub_hash: generate_peer_hash(peerkey),
        signature: signed.to_vec(),
        timestamp,
    };
    let payload_bytes = rmp_serde::to_vec(&purge_payload)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    let msg =
        generate_blob(peerkey, payload_bytes).map_err(|_| ClientErrors::KeyDerivationFailed)?;
    Ok(ClientToServer::new(msg, None))
}
pub fn generate_offline_message(
    peer_pub: &PublicKey,
    cipher: Vec<u8>,
    signing: &SigningKey,
) -> Result<ClientToServer, ClientErrors> {
    let timestamp = Utc::now().timestamp();
    let bytes_to_sign = [
        b"offline".as_slice(),
        cipher.as_slice(),
        &timestamp.to_le_bytes(),
    ]
    .concat();
    let signed = sign_challenge(signing, bytes_to_sign.as_slice());
    let offline_payload = BlobPayload::OfflineMessage {
        sender_pub_hash: generate_peer_hash(peer_pub),
        signature: signed.to_vec(),
        timestamp,
        ciphertext: cipher,
    };
    let payload_bytes = rmp_serde::to_vec(&offline_payload)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    let msg =
        generate_blob(peer_pub, payload_bytes).map_err(|_| ClientErrors::KeyDerivationFailed)?;
    Ok(ClientToServer::new(msg, None))
}
pub fn generate_lookup_message(peer_pub: &PublicKey) -> ClientToServer {
    ClientToServer::new(
        ClientMessage::LookupPeer {
            token: generate_peer_hash(peer_pub),
        },
        None,
    )
}

pub fn generate_peer_hash(peer_pub: &PublicKey) -> [u8; 32] {
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

pub fn generate_p2p_request(
    peer_pub: &PublicKey,
    privkey: &StaticSecret,
) -> Result<ClientMessage, ClientErrors> {
    let token = presence_token(privkey, peer_pub, Utc::now().timestamp())
        .map_err(|_| ClientErrors::EncryptionFailed)?;
    Ok(ClientMessage::RequestHolePunch { token })
}
