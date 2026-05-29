use argon2::{Argon2, password_hash};
use chacha20poly1305::{
    ChaCha20Poly1305, ChaChaPoly1305, Key, KeyInit, Nonce,
    aead::{Aead, AeadCore},
};
use chrono::Utc;
use ed25519_dalek::*;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as hmackeyinit, Mac};
use home::home_dir;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, IVec};
use std::sync::OnceLock;
use std::{fmt, fs::remove_dir_all};
use std::{
    fs::{self, OpenOptions, metadata},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
static SECHAT_DIR: OnceLock<PathBuf> = OnceLock::new();
static PEERS_DIR: OnceLock<PathBuf> = OnceLock::new();
#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Author {
    You,
    Peer,
}
pub struct Messages {
    data: Vec<Message>,
    peer: String,
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Message {
    author: Author,
    text: String,
    timestamp: i64,
}
impl Message {
    fn new(text: String, author: Author) -> Self {
        let timestamp: i64 = Utc::now().timestamp();
        Message {
            text,
            author,
            timestamp,
        }
    }
}
pub fn sechat_dir() -> &'static PathBuf {
    SECHAT_DIR.get_or_init(|| home_dir().expect("Failed to get home path").join(".sechat"))
}

pub fn peers_dir() -> &'static PathBuf {
    PEERS_DIR.get_or_init(|| sechat_dir().join("peers"))
}
pub type KeyType = [u8; 32];
pub type HmacSha256 = Hmac<Sha256>;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;
pub enum CryptoErrors {
    CryptographicError,
    NotADirectory(String),
    PermissionDenied,
    BadPermission,
    NotFound(String),
    Other(std::io::Error),
    CorruptedFile,
}

impl fmt::Display for CryptoErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoErrors::CryptographicError => write!(f, "Cryptographic error"),
            CryptoErrors::NotADirectory(s) => write!(f, "Not a directory: {}", s),
            CryptoErrors::PermissionDenied => write!(f, "Permission denied"),
            CryptoErrors::BadPermission => write!(f, "Bad file permission"),
            CryptoErrors::NotFound(s) => write!(f, "Not found: {}", s),
            CryptoErrors::Other(e) => write!(f, "IO error: {}", e),
            CryptoErrors::CorruptedFile => write!(f, "Corrupted file"),
        }
    }
}

impl fmt::Debug for CryptoErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for CryptoErrors {}
pub struct FileData {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    pubkey: Vec<u8>,
}

pub struct Keys {
    pub x25519_priv: StaticSecret,
    pub x25519_pub: PublicKey,
    pub ed25519_signing: SigningKey,
    pub ed25519_verifying: VerifyingKey,
}

pub fn generate_x25519() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn generate_ed25519() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn encrypt_keyfile(
    passwdplain: String,
    x25519_priv: StaticSecret,
    x25519_pub: PublicKey,
    ed25519_signing: SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // połącz oba priv_key w jeden plaintext 64B
    let mut plaintext = [0u8; 64];
    plaintext[..32].copy_from_slice(&x25519_priv.to_bytes());
    plaintext[32..].copy_from_slice(ed25519_signing.as_bytes());

    let mut derived_filekey = [0u8; 32];
    Argon2::default()
        .hash_password_into(passwdplain.as_bytes(), &salt, &mut derived_filekey)
        .map_err(|e| format!("Argon2 error: {}", e))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_filekey));
    let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext: Vec<u8> = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| format!("Encrypt error: {}", e))?;

    // zeroize plaintext po szyfrowaniu
    plaintext.zeroize();
    derived_filekey.zeroize();

    let base_dir = sechat_dir();
    fs::create_dir_all(base_dir)?;
    fs::create_dir_all(peers_dir())?;

    let mut options = OpenOptions::new();
    options.write(true).truncate(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);

    // [sól 32B][nonce 12B][ciphertext 80B] = 124B
    let writeable = [salt.as_slice(), nonce.as_slice(), ciphertext.as_slice()].concat();
    let mut file = options.open(base_dir.join("identity.key"))?;
    file.write_all(&writeable)?;
    file.flush()?;

    // [x25519_pub 32B][ed25519_verifying 32B] = 64B
    let mut pub_bytes = [0u8; 64];
    pub_bytes[..32].copy_from_slice(x25519_pub.as_bytes());
    pub_bytes[32..].copy_from_slice(ed25519_signing.verifying_key().as_bytes());
    let mut file = options.open(base_dir.join("identity.pub"))?;
    file.write_all(&pub_bytes)?;
    file.flush()?;

    Ok(())
}

pub fn read_keyfile() -> Result<FileData, CryptoErrors> {
    // 32(sól) + 12(nonce) + 80(ciphertext) = 124B
    let privkeybuf = read_file_to_buffer(sechat_dir().join("identity.key"), 124)?;
    let salt = privkeybuf[..32].to_vec();
    let nonce = privkeybuf[32..44].to_vec();
    let ciphertext = privkeybuf[44..124].to_vec();

    // 32(x25519_pub) + 32(ed25519_verifying) = 64B
    let pubkeybuf = read_file_to_buffer(sechat_dir().join("identity.pub"), 64)?;
    let pubkey = pubkeybuf[..].to_vec();

    Ok(FileData {
        salt,
        nonce,
        ciphertext,
        pubkey,
    })
}

pub fn decrypt_keyfile(password: String, file_data: FileData) -> Result<Keys, CryptoErrors> {
    let mut derived_filekey = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &file_data.salt, &mut derived_filekey)
        .map_err(|_| CryptoErrors::CryptographicError)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_filekey));
    let nonce = Nonce::from_slice(&file_data.nonce);
    let plaintext = cipher
        .decrypt(nonce, file_data.ciphertext.as_slice())
        .map_err(|_| CryptoErrors::PermissionDenied)?;

    derived_filekey.zeroize();

    // x25519
    let x25519_bytes: KeyType = plaintext[..32]
        .try_into()
        .map_err(|_| CryptoErrors::CorruptedFile)?;
    let x25519_priv = StaticSecret::from(x25519_bytes);
    let x25519_pub = PublicKey::from(&x25519_priv);

    // ed25519
    let ed25519_bytes: KeyType = plaintext[32..64]
        .try_into()
        .map_err(|_| CryptoErrors::CorruptedFile)?;
    let ed25519_signing = SigningKey::from_bytes(&ed25519_bytes);
    let ed25519_verifying = ed25519_signing.verifying_key();

    Ok(Keys {
        x25519_priv,
        x25519_pub,
        ed25519_signing,
        ed25519_verifying,
    })
}

pub fn read_file_to_buffer(filename: PathBuf, sizeinbytes: usize) -> Result<Vec<u8>, CryptoErrors> {
    let mut buf = vec![0u8; sizeinbytes];

    let mut file = OpenOptions::new()
        .read(true)
        .open(filename)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => CryptoErrors::PermissionDenied,
            _ => CryptoErrors::Other(e),
        })?;
    file.read_exact(&mut buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => CryptoErrors::CorruptedFile,
        std::io::ErrorKind::PermissionDenied => CryptoErrors::PermissionDenied,
        _ => CryptoErrors::Other(e),
    })?;
    Ok(buf)
}

fn initialize_peer(
    peer_pub: &PublicKey,
    privkey: &StaticSecret,
) -> Result<(Key, Key), CryptoErrors> {
    let sechat_path = peers_dir().join(hex::encode(Sha256::digest(peer_pub.as_bytes())));

    fs::create_dir_all(&sechat_path).map_err(|e| CryptoErrors::Other(e))?;
    let mut peer_pub_f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(sechat_path.join("peer.pub"))
        .map_err(|e| CryptoErrors::Other(e))?;
    peer_pub_f
        .write_all(peer_pub.as_bytes())
        .map_err(|e| CryptoErrors::Other(e))?;
    peer_pub_f.flush().map_err(|e| CryptoErrors::Other(e))?;

    let shared = privkey.diffie_hellman(peer_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());

    let mut session_key = [0u8; 32];
    hk.expand(b"session", &mut session_key)
        .map_err(|_| CryptoErrors::CryptographicError)?;

    let mut storage_key = [0u8; 32];
    hk.expand(b"storage", &mut storage_key)
        .map_err(|_| CryptoErrors::CryptographicError)?;

    Ok((Key::from(session_key), Key::from(storage_key)))
}

pub fn load_peer_data(hash: &[u8]) -> Result<PublicKey, CryptoErrors> {
    let hex = hex::encode(hash);
    let peer_dir = peers_dir().join(&hex);
    if !peer_dir.is_dir() {
        return Err(CryptoErrors::NotFound(hex));
    }
    let buf = read_file_to_buffer(peer_dir.join("peer.pub"), 32)?;
    let pub_bytes: KeyType = buf
        .as_slice()
        .try_into()
        .map_err(|_| CryptoErrors::CorruptedFile)?;
    Ok(PublicKey::from(pub_bytes))
}

pub fn encrypt_message_for_chat(message: String, sessionkey: Key, counter: u64) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, sessionkey.as_slice());
    let mut message_key = [0u8; 32];
    hk.expand(b"message", &mut message_key).unwrap();
    let mut nonce: [u8; 12] = [0u8; 12];
    hk.expand(b"nonce", &mut nonce).unwrap();
    let nonce: Nonce = nonce_for_message(&nonce, counter);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key));
    cipher.encrypt(&nonce, message.as_bytes()).unwrap()
}

fn nonce_for_message(base: &[u8; 12], counter: u64) -> Nonce {
    let mut n = *base;
    let counter_bytes = counter.to_le_bytes();
    for i in 0..8 {
        n[4 + i] ^= counter_bytes[i];
    }
    Nonce::from(n)
}

pub fn decrypt_message_from_chat(
    message: Vec<u8>,
    sessionkey: Key,
    counter: u64,
) -> Result<String, CryptoErrors> {
    let hk = Hkdf::<Sha256>::new(None, sessionkey.as_slice());
    let mut message_key = [0u8; 32];
    hk.expand(b"message", &mut message_key).unwrap();
    let mut nonce: [u8; 12] = [0u8; 12];
    hk.expand(b"nonce", &mut nonce).unwrap();
    let nonce = nonce_for_message(&nonce, counter);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key));
    let decrypted = cipher
        .decrypt(&nonce, message.as_slice())
        .map_err(|_| CryptoErrors::CryptographicError)?;

    String::from_utf8(decrypted).map_err(|_| CryptoErrors::CorruptedFile)
}

pub fn load_storage_key(peer_pub: &PublicKey, privkey: &StaticSecret) -> Result<Key, CryptoErrors> {
    let shared = privkey.diffie_hellman(peer_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut storage: KeyType = [0u8; 32];
    hk.expand(b"storage", &mut storage)
        .map_err(|_| CryptoErrors::CryptographicError)?;
    Ok(Key::from(storage))
}
pub fn purge(path: Option<PathBuf>, mut privkey: StaticSecret) -> Result<(), CryptoErrors> {
    privkey.zeroize();
    let path = path.unwrap_or_else(|| sechat_dir().clone());
    remove_dir_all(path).map_err(CryptoErrors::Other)
}

pub fn presence_token(
    privkey: &StaticSecret,
    peer_pub: PublicKey,
    timestamp: u64,
) -> Result<KeyType, CryptoErrors> {
    let shared = privkey.diffie_hellman(&peer_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut presence_key: KeyType = [0u8; 32];
    hk.expand(b"presence", &mut presence_key)
        .map_err(|_| CryptoErrors::CryptographicError)?;
    let ts = (timestamp / 15) * 15;
    let mut mac =
        HmacSha256::new_from_slice(&presence_key).map_err(|_| CryptoErrors::CryptographicError)?;
    mac.update(&ts.to_le_bytes());
    let result: KeyType = mac
        .finalize()
        .into_bytes()
        .try_into()
        .map_err(|_| CryptoErrors::CryptographicError)?;
    Ok(result.into())
}

pub fn verify_challenge(
    verif: VerifyingKey,
    bits: &[u8],
    signature: &Signature,
) -> Result<(), CryptoErrors> {
    verif
        .verify(bits, signature)
        .map_err(|_| CryptoErrors::CryptographicError)
}
pub fn sign_challenge(signing: &SigningKey) -> (Signature, KeyType) {
    let mut bytes: KeyType = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let signature = signing.sign(&bytes);
    (signature, bytes)
}
pub fn load_peers() -> Result<Vec<PublicKey>, CryptoErrors> {
    let peersdir = peers_dir();
    peersdir
        .read_dir()
        .map_err(|_| {
            CryptoErrors::NotFound(
                peersdir
                    .clone()
                    .into_os_string()
                    .into_string()
                    .to_owned()
                    .unwrap(),
            )
        })?
        .map(|entry| -> Result<PublicKey, CryptoErrors> {
            let peerdir = entry.map_err(CryptoErrors::Other)?.path();
            let mut f = fs::OpenOptions::new()
                .read(true)
                .open(peerdir.join("peer.pub"))
                .map_err(CryptoErrors::Other)?;
            let mut buf: KeyType = [0u8; 32];
            f.read_exact(&mut buf).map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => CryptoErrors::CorruptedFile,
                _ => CryptoErrors::Other(e),
            })?;
            Ok(PublicKey::from(buf))
        })
        .collect::<Result<Vec<_>, _>>()
}
pub fn derive_session_key(
    ephermal_priv: &StaticSecret,
    peer_ephemeral_pub: &PublicKey,
) -> Result<Key, CryptoErrors> {
    let shared = ephermal_priv.diffie_hellman(peer_ephemeral_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut session_key: KeyType = [0u8; 32];
    hk.expand(b"session", &mut session_key)
        .map_err(|_| CryptoErrors::CryptographicError);
    Ok(Key::from(session_key))
}
pub fn load_peer_chat(key: &PublicKey, storagekey: Key) -> Result<Messages, CryptoErrors> {
    let hex_path = hex::encode(Sha256::digest(key.as_bytes()));
    let path = peers_dir().as_path().join(&hex_path).join("chat.db");
    let mut msgvec: Vec<Message> = vec![];
    let db = sled::open(path).map_err(|_| CryptoErrors::CorruptedFile)?;
    let to_remove: Vec<IVec> = db
        .iter()
        .filter_map(|item| {
            let (key, value) = item.ok()?;

            match decrypt_message_stored(&value.to_vec(), &storagekey) {
                Ok(item) => match rmp_serde::from_slice::<Message>(&item) {
                    Ok(msg) => {
                        msgvec.push(msg);
                        None
                    }

                    Err(_) => Some(key),
                },
                Err(_) => Some(key),
            }
        })
        .collect();
    for key in to_remove {
        db.remove(key).ok();
    }
    Ok(Messages {
        data: msgvec,
        peer: hex_path,
    })
}
pub fn insert_message() {}

pub fn insert_message_stored(msg: Message, storagekey: Key, db: Db) -> Result<(), CryptoErrors> {
    let encrypted_data = encrypt_message_stored(&msg, &storagekey)?;
    let counter: u64 = match db.last().map_err(|_| CryptoErrors::CorruptedFile)? {
        Some((key, _)) => {
            let last: u64 = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| CryptoErrors::CorruptedFile)?,
            );
            last + 1
        }
        None => 0,
    };

    let ivec: IVec = encrypted_data.into();
    db.insert((counter).to_be_bytes(), ivec)
        .map_err(|_| CryptoErrors::CorruptedFile)?;
    Ok(())
}

pub fn decrypt_message_stored(data: &Vec<u8>, storagekey: &Key) -> Result<Vec<u8>, CryptoErrors> {
    if data.len() < 12 {
        return Err(CryptoErrors::CorruptedFile);
    }
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(storagekey);
    let nonce = &data[0..12];
    let ciphertext = &data[12..];
    let nonce = Nonce::from_slice(nonce);
    if let Ok(plainbytes) = cipher.decrypt(nonce, ciphertext) {
        Ok(plainbytes)
    } else {
        Err(CryptoErrors::CryptographicError)
    }
}

pub fn encrypt_message_stored(msg: &Message, storagekey: &Key) -> Result<Vec<u8>, CryptoErrors> {
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(storagekey);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let bytes = rmp_serde::to_vec(&msg).map_err(|_| CryptoErrors::CryptographicError)?;
    let ciphertext = cipher
        .encrypt(&nonce, bytes.as_slice())
        .map_err(|_| CryptoErrors::CryptographicError)?;
    let data: Vec<u8> = [nonce.as_slice(), ciphertext.as_slice()].concat();
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encryption_chat() {
        let (private, public) = generate_x25519();
        let sessionkey = derive_session_key(&private, &public).unwrap();
        let encrypted_data = encrypt_message_for_chat("Hi".to_owned(), sessionkey, 0);
        let decrypted_data = decrypt_message_from_chat(encrypted_data, sessionkey, 0).unwrap();
        assert_eq!(decrypted_data, "Hi".to_owned())
    }
    #[test]
    fn test_encryption_storage() {
        let (private, public) = generate_x25519();
        let storagekey = load_storage_key(&public, &private).unwrap();
        let msg = Message::new("Hi".to_owned(), Author::You);
        let encrypted_data = encrypt_message_stored(&msg, &storagekey).unwrap();
        let decrypted_data = decrypt_message_stored(&encrypted_data, &storagekey).unwrap();
        let final_item = rmp_serde::from_slice::<Message>(&decrypted_data).unwrap();
        assert_eq!(msg, final_item)
    }
}
