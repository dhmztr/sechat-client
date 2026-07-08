use crate::*;

pub fn generate_authenticate_message(
    public: [u8; 32],
    verif: [u8; 32],
    signing: &SigningKey,
    timestamp: i64,
) -> Result<ClientToServer, CryptoErrors> {
    let data_to_sign = [
        public.as_slice(),
        verif.as_slice(),
        &timestamp.to_le_bytes(),
    ]
    .concat();
    let data = sign_challenge(signing, &data_to_sign);
    let payload = ClientMessage::Auth {
        pub_key: public,
        verif,
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
    recipient: &PeerPublic,
    message: Vec<u8>,
) -> Result<ClientMessage, CryptoErrors> {
    let blob = encrypt_blob(&recipient.public, &message)?;
    Ok(ClientMessage::SendBlob {
        recipient_hash: generate_peer_hash(recipient),
        blob,
    })
}

pub fn generate_purge_message(
    recipient: &PeerPublic,
    my_pub: &PublicKey,
    sign: &SigningKey,
) -> Result<ClientToServer, ClientErrors> {
    let timestamp = Utc::now().timestamp();
    let bytes_to_sign = [b"purge".as_slice(), &timestamp.to_le_bytes()].concat();

    let signed = sign_challenge(sign, bytes_to_sign.as_slice());
    let purge_payload = BlobPayload::Purge {
        sender_pub_hash: identity_hash(my_pub, &sign.verifying_key()),
        signature: signed.to_vec(),
        timestamp,
    };
    let payload_bytes = rmp_serde::to_vec(&purge_payload)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    let msg =
        generate_blob(recipient, payload_bytes).map_err(|_| ClientErrors::KeyDerivationFailed)?;
    Ok(ClientToServer::new(msg, None))
}
pub fn generate_offline_message(
    recipient: &PeerPublic,
    my_pub: &PublicKey,
    my_priv: &StaticSecret,
    text: String,
    signing: &SigningKey,
) -> Result<ClientToServer, ClientErrors> {
    let timestamp = Utc::now().timestamp();
    let storage_key = load_storage_key(&recipient.public, my_priv)
        .map_err(|_| ClientErrors::KeyDerivationFailed)?;
    let stored_msg = crypto::Message::from_parts(text, crypto::Author::You, timestamp);
    let cipher = encrypt_message_stored(&stored_msg, &storage_key)
        .map_err(|_| ClientErrors::EncryptionFailed)?;
    let bytes_to_sign = [
        b"offline".as_slice(),
        cipher.as_slice(),
        &timestamp.to_le_bytes(),
    ]
    .concat();
    let signed = sign_challenge(signing, bytes_to_sign.as_slice());
    let offline_payload = BlobPayload::OfflineMessage {
        sender_pub_hash: identity_hash(my_pub, &signing.verifying_key()),
        signature: signed.to_vec(),
        timestamp,
        ciphertext: cipher,
    };
    let payload_bytes = rmp_serde::to_vec(&offline_payload)
        .map_err(|e| ClientErrors::SerializationFailed(e.to_string()))?;
    let msg =
        generate_blob(recipient, payload_bytes).map_err(|_| ClientErrors::KeyDerivationFailed)?;
    Ok(ClientToServer::new(msg, None))
}
pub fn generate_lookup_message(peer: &PeerPublic) -> ClientToServer {
    ClientToServer::new(
        ClientMessage::LookupPeer {
            token: generate_peer_hash(peer),
        },
        None,
    )
}

pub fn generate_peer_hash(peer: &PeerPublic) -> [u8; 32] {
    identity_hash(&peer.public, &peer.verifying)
}

pub fn generate_peer_lookup(peer: &PeerPublic) -> ClientMessage {
    ClientMessage::LookupPeer {
        token: generate_peer_hash(peer),
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
