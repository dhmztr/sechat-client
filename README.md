# sechat

**Experimental peer-to-peer encrypted chat protocol and reference implementation in Rust.**

> ⚠️ **This is a research project, not audited cryptographic software.** Do not use for anything where compromise would cause real harm.

---

## Overview

sechat is a peer-to-peer chat protocol designed for 1-to-1 conversations with strong privacy guarantees. The system is built around three principles:

1. **No central server sees plaintext or knows who talks to whom.** A minimal server exists only for presence signaling and offline message storage. It handles encrypted blobs addressed to anonymous hashes.
2. **Identity is local to the machine.** Private keys never leave the device. There is no account, no recovery, no key sync. Compromising a device means generating a new identity.
3. **Conversations are end-to-end encrypted with forward secrecy.** Message keys are derived per-session from ephemeral Diffie-Hellman. History is encrypted at rest with a deterministic key derived from long-term identity keys.

---

## Threat Model

### What sechat protects against

- **Passive network observers** — all traffic is encrypted; metadata visible to the server is decoupled from identity.
- **Malicious or compromised server** — the server only sees opaque blobs addressed to hashes and rotating random tokens. It cannot link identity to traffic.
- **Future key compromise** — past sessions remain confidential because session keys are ephemeral (forward secrecy).
- **Remote attackers** — private keys live encrypted on disk; without the user's password they are inert.
- **Man-in-the-middle on first contact** — public keys are exchanged out-of-band, not through the server.

### What sechat does NOT protect against

- **Physical access with the password** — if an attacker has both the device and the password, they have everything.
- **Endpoint compromise during a session** — once private keys are unlocked in RAM, malware on the device can read everything.
- **Traffic analysis at ISP level** — the server cannot identify users, but an ISP observing both endpoints could correlate timing.
- **Loss of the device** — there is no backup, no recovery. Lost device equals lost history.
- **Coercion** — the protocol cannot help a user forced to reveal their password.

---

## Architecture

### Cryptographic Primitives

| Purpose               | Algorithm                |
| --------------------- | ------------------------ |
| Identity & signatures | Ed25519                  |
| Key agreement (ECDH)  | X25519                   |
| Symmetric encryption  | ChaCha20-Poly1305 (AEAD) |
| Key derivation        | HKDF-SHA256              |
| Password hashing      | Argon2id                 |
| Presence tokens       | HMAC-SHA256              |
| Address derivation    | SHA-256                  |

### Identity

Each user owns two long-term keypairs:

- **Ed25519** — used for signing challenges during connection establishment. The verifying key serves as the user's stable identifier.
- **X25519** — used for ECDH to derive shared secrets with peers.

Private keys are stored on disk encrypted with a password-derived key:

```
file: ~/.sechat/identity.key
layout: [salt 32B][nonce 12B][ciphertext 80B]
ciphertext = ChaCha20-Poly1305(
    key = Argon2id(password, salt),
    plaintext = x25519_priv (32B) || ed25519_priv (32B)
)
```

Public keys are stored plaintext:

```
file: ~/.sechat/identity.pub
layout: [x25519_pub 32B][ed25519_verifying 32B]
```

Identity is bound to the device. There is no synchronization across machines.

---

## Protocol

### 1. Out-of-band Key Exchange

Users exchange public keys through a separate channel (a companion secret-sharing app, QR code, SMS, in-person). The server is never trusted to introduce two users.

This step is the trust anchor of the system. If the public key is delivered authentically, no man-in-the-middle is possible on subsequent operations.

### 2. Friend Request

Once Bob has Alice's public key:

```
Bob → Server: encrypt(alice_pub, bob_pub || "request")
              addressed to sha256(alice_pub)
Server: stores the encrypted blob under the hash
Alice → Server: fetch blobs for sha256(alice_pub)
Alice: decrypt with her private key, sees bob_pub + intent
```

If Alice accepts:

```
Alice → Server: encrypt(bob_pub, alice_pub || "accepted")
Bob: fetch, decrypt, friendship established
```

The server sees only encrypted blobs addressed to hashes. It cannot determine who is messaging whom.

### 3. Presence

Once mutual acquaintance is established, both parties derive a shared presence key:

```
presence_key = HKDF(ECDH(my_priv, peer_pub), info = "presence")
```

To announce online status, the client computes a rotating token:

```
token = HMAC(presence_key, floor(timestamp / 15) * 15)
client → server: announce(token, ip:port)
```

A friend who wants to find this user computes the same token independently:

```
client → server: lookup(token)
server → client: ip:port
```

Because the token is derived from a shared secret, the server cannot link tokens to identities. Each friendship produces a distinct token; the server sees only random values.

### 4. Peer-to-Peer Connection

After locating a peer's IP:port through presence, clients establish a direct connection:

1. **IPv6 first** — if both peers have public IPv6, connect directly.
2. **UDP hole punching** — for IPv4 NAT, both clients send simultaneous packets to each other's external addresses. Synchronization is achieved through the same 15-second window used for presence tokens.
3. **TURN relay fallback** — for symmetric NAT or restrictive firewalls, a self-hosted relay forwards encrypted packets.

### 5. Session Establishment

Once a direct connection exists, peers establish an encrypted session with forward secrecy:

```
Each side generates an ephemeral X25519 keypair.
Public ephemeral keys are exchanged.
session_key = HKDF(ECDH(ephemeral_priv, peer_ephemeral_pub), info = "session")
```

Identity is authenticated via Ed25519 challenge-response:

```
Bob → Alice: challenge = random_32_bytes
Alice → Bob: Ed25519_sign(alice_signing_key, challenge)
Bob: verify with alice_verifying_key (known from out-of-band exchange)
```

The challenge prevents impersonation. The ephemeral keypair ensures that compromise of long-term keys does not expose past sessions.

### 6. Message Encryption

Messages are encrypted with a key derived from `session_key`, and nonces are derived deterministically from a counter:

```
message_key = HKDF(session_key, info = "message")
base_nonce  = HKDF(session_key, info = "nonce")
nonce_for_message_n = base_nonce XOR counter_n
ciphertext = ChaCha20-Poly1305(message_key, nonce, plaintext)
```

This avoids transmitting nonces over the wire while guaranteeing uniqueness, provided the counter is monotonic within a session.

### 7. Local Storage

Conversation history is encrypted on disk with a deterministic key derived from long-term identity:

```
storage_key = HKDF(ECDH(identity_priv, peer_pub), info = "storage")
```

Because this key is deterministic, it does not need to be stored separately. It is re-derived whenever the user unlocks their identity.

Each peer is stored in a directory addressed by the hash of their public key:

```
~/.sechat/peers/<sha256(peer_pub) as hex>/
    peer.pub        # peer's public key (plaintext, 32B)
    chat.log        # encrypted message history
```

No filesystem metadata leaks the peer's identity beyond the hash.

### 8. Offline Messages

When a peer is offline, messages queue locally:

```
Bob writes a message → encrypt with storage_key → append to local outbox
When Alice comes online → Bob sends queued messages directly P2P
```

The server is only involved when both parties are offline for an extended period and the sender wants delivery guarantee. In that case, the encrypted blob goes to the mailbox server, identical to friend requests.

### 9. History Synchronization

When two peers reconnect after being offline:

```
Alice → Bob: my last message timestamp T_A
Bob   → Alice: my last message timestamp T_B
Bob sends Alice: all messages he authored after T_A
Alice sends Bob: all messages she authored after T_B
Ordering: timestamp + author_id as tiebreaker
```

Because conversations are 1-to-1 and append-only with disjoint authorship, no conflict resolution (CRDT) is required.

---

## Server

The server is intentionally minimal and handles two responsibilities:

1. **Presence registry** — maps rotating tokens to ip:port. Entries are in-memory; clients re-announce when reconnecting.
2. **Mailbox** — store-and-forward for encrypted blobs addressed to hashes. Blobs are deleted on client acknowledgment.

### Transport

Communication is over a single WebSocket connection per client, multiplexed with MessagePack-encoded messages. A bidirectional stream carries:

- Client → Server: authentication, presence announcement, blob upload, blob acknowledgment.
- Server → Client: pending blobs (pushed on connect and when new ones arrive), peer online/offline notifications.

### Authentication

Each WebSocket connection begins with a signed authentication message:

```
{
    pub_key,
    timestamp,
    signature = Ed25519(priv_key, timestamp)
}
```

The server verifies the signature and rejects timestamps outside a ±30 second window (replay protection). It does not maintain accounts; the public key is the identity for the duration of the connection.

### What the server sees

| Component        | Visible to server                                  | Invisible to server                   |
| ---------------- | -------------------------------------------------- | ------------------------------------- |
| Mailbox          | `sha256(recipient_pub)`, encrypted blob, timestamp | plaintext, sender, recipient identity |
| Presence         | rotating token, ip:port, timestamp                 | which user, who is querying           |
| Friendship graph | nothing                                            | who is friends with whom              |

---

## Compromise & Recovery

### Identity compromise

If a private key is compromised, the user performs a **purge**:

1. Generate a new keypair.
2. For each friend, send a "PURGE + new_pub_key" message encrypted under the old key.
3. Delete `~/.sechat/` including all stored history.
4. Re-establish out-of-band with each contact using the new key.

Because storage keys are derived from identity keys, old encrypted history becomes permanently inaccessible after the purge. This is a deliberate property, not a bug — it prevents past data from being decrypted by an attacker who later obtains the old keys.

### Device-level verification

On each reconnection, identity is reverified with a fresh Ed25519 challenge. If a friend's signing key changes unexpectedly, the client surfaces a warning. The user must verify the new key out-of-band before continuing.

### Message deletion

Either party can initiate deletion of conversation history. Both clients must consent; on agreement, both delete their local encrypted logs. There is no mechanism to force deletion on the other side — this is inherent to peer-to-peer systems without central authority.

---

## Implementation

### Crate dependencies

```
ed25519-dalek         identity and signatures
x25519-dalek          ECDH
chacha20poly1305      symmetric AEAD encryption
argon2                password-based key derivation
hkdf + sha2           key derivation
hmac + sha2           presence tokens
rand_core             secure randomness
zeroize               clear secrets from RAM
home                  cross-platform home directory
sled                  embedded encrypted storage
hex                   address encoding

axum + tokio          server (WebSocket)
rmp-serde             MessagePack serialization
dashmap               concurrent presence registry

iced                  GUI (MVU architecture)
notify-rust           desktop notifications
```

### Filesystem layout

```
~/.sechat/
├── identity.key            encrypted private keys
├── identity.pub            public keys
└── peers/
    └── <hash-hex>/
        ├── peer.pub        friend's public key
        └── chat.log        encrypted message history
```

### Stage

Stage 1 (in progress): cryptographic layer
- [x] Identity keypair generation and encrypted persistence
- [x] Key derivation architecture (HKDF domain separation)
- [x] encrypt_data / decrypt_data implementation
- [x] Session key establishment
- [x] Read sled database for each peer
- [ ] 
- [ ] Server transport

---

## Design Trade-offs

| Decision                  | Trade-off                                                        |
| ------------------------- | ---------------------------------------------------------------- |
| Identity bound to device  | Maximum privacy, no recovery if device fails                     |
| Deterministic storage key | No key file to manage, but compromised identity exposes history  |
| Out-of-band key exchange  | Eliminates need for trusted key directory, requires user effort  |
| Local-only offline queue  | No server-side metadata, but requires sender online for delivery |
| Single-server presence    | Simplicity over federation                                       |
| No group chats            | 1-to-1 only; group cryptography is significantly harder          |

---

## Status

This is an early-stage research project. The cryptographic protocol has not been formally reviewed. The implementation is incomplete. Do not use sechat for sensitive communication.

Contributions, protocol critique, and review are welcome.
