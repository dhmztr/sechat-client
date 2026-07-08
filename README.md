# sechat

[![CI](https://github.com/Lukidere/sechat-client/actions/workflows/ci.yml/badge.svg)](https://github.com/Lukidere/sechat-client/actions/workflows/ci.yml)

**Experimental peer-to-peer encrypted chat protocol and reference implementation in Rust.**

> ⚠️ **This is a research project, not audited cryptographic software.** Do not use for anything where compromise would cause real harm.

---

## Overview

sechat is a peer-to-peer chat protocol designed for 1-to-1 conversations with strong privacy guarantees. The system is built around three principles:

1. **No central server sees plaintext.** A minimal server handles presence signaling, offline message storage, STUN discovery, and brokering/relaying P2P connections. It only ever moves encrypted blobs addressed to identity hashes — never plaintext. (It does route by those hashes, so it can observe the communication graph; see the threat model.)
2. **Identity is local to the machine.** Private keys never leave the device. There is no account, no recovery, no key sync. Compromising a device means generating a new identity.
3. **Conversations are end-to-end encrypted with forward secrecy.** Message keys are derived per-session from ephemeral Diffie-Hellman. History is encrypted at rest with a deterministic key derived from long-term identity keys.

---

## Building and Running

The workspace has three front-ends: a relay **server** (`seserver`, a separate
crate), a **GUI** client (`iced`), and a headless **CLI** client.

```bash
# build everything
cd client && cargo build --workspace
cd ../seserver && cargo build
```

### Run the relay server

Production uses `wss://` and requires a TLS cert/key:

```bash
cd seserver
TLS_CERT=./cert.pem TLS_KEY=./key.pem cargo run
```

For local testing without certificates, set `SECHAT_DEV_INSECURE=1` to serve plain
`ws://` (the client honours the same flag). The server also runs a UDP STUN
responder on `STUN_PORT` (default 3478).

### Run a client

```bash
cd client
# GUI
cargo run -p gui
# CLI
cargo run -p client --bin sechat-cli
```

On first launch you set a password (creating an encrypted identity) and the relay
address. Useful environment variables:

| Variable              | Meaning                                               |
| --------------------- | ----------------------------------------------------- |
| `SECHAT_DEV_INSECURE` | Connect over plain `ws://` (must match the server)    |
| `SECHAT_DEBUG`        | Verbose tracing (client stderr / server `tracing`)    |
| `SECHAT_SERVER`       | Override the saved relay address                      |
| `SECHAT_STUN`         | Override the STUN address (default: server host:3478) |
| `HOME`                | Data dir root (`$HOME/.sechat`) — set per instance    |

### Two peers on one machine

```bash
# terminal 1 — relay
cd seserver && SECHAT_DEV_INSECURE=1 cargo run
# terminals 2 & 3 — two identities via separate HOME dirs
HOME=/tmp/a SECHAT_DEV_INSECURE=1 cargo run -p gui
HOME=/tmp/b SECHAT_DEV_INSECURE=1 cargo run -p client --bin sechat-cli
```

Each client shows its two public keys (GUI **Options** panel / CLI `mykeys`). Peers
add each other by pasting those keys, then chat. Direct P2P is used when the punch
succeeds, otherwise the relay carries the (still end-to-end encrypted) messages.

### CLI commands

`peers`, `add <x25519_hex> <verif_hex>`, `alias <peer> <name>`, `connect <peer>`,
`msg <peer> <text>`, `history <peer>`, `purge <peer>`, `mykeys`, `server [host:port]`,
`help`, `quit`. A `<peer>` may be an alias, alias prefix, or fingerprint prefix.

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

### 2. Adding a Peer

There is no server-mediated friend-request handshake. Adding a peer is a local
operation: each side takes the other's two public keys (x25519 + ed25519, obtained
out-of-band) and stores them.

```
Bob has alice_x25519 + alice_verifying
Bob: initialize_peer(alice_x25519, alice_verifying)
     -> writes peers/hex(id)/peer.pub  (id = sha256(x25519 ‖ ed25519))
```

Once both sides have added each other they can announce presence, connect, and
exchange messages. The keys never pass through the server.

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

After locating a peer's UDP address through presence, clients establish a direct connection:

1. **STUN discovery** — each client asks the server's UDP STUN responder for its public mapping (over the same socket it will punch with) and announces that address.
2. **UDP hole punching** — the relay brokers the punch and hands each peer the other's address; both send simultaneous pings using a shared server-issued timestamp so their NATs open in sync.
3. **TURN relay fallback** — if the punch fails (symmetric NAT, restrictive firewall), the server forwards the encrypted session frames. This works for any pair that can both reach the relay.

### 5. Session Establishment

Each client keeps one persistent UDP socket and discovers its public mapping from
a STUN responder on the server, then announces that address for presence. The relay
brokers the hole punch and hands each peer the other's UDP address; both punch
simultaneously using a shared server-issued timestamp.

Over the punched socket, each side exchanges a single signed `Init`:

```
Each side generates an ephemeral X25519 keypair.
Each sends PeerMessage::Init(ephemeral_pub), Ed25519-signed.
The receiver verifies the signature against the peer's known verifying key.
session_key = HKDF(ECDH(my_ephemeral_priv, peer_ephemeral_pub), info = "session")
```

Every frame is Ed25519-signed and carries a strictly increasing counter; replayed or
out-of-order frames are dropped. Each direction derives a distinct key from the
session key (`a2b` / `b2a`) so the two peers never reuse a ChaCha20 nonce. Compromise
of long-term keys does not expose past direct sessions (ephemeral forward secrecy).

**Relay fallback.** If the punch fails (symmetric NAT, restrictive firewall), the
session tunnels the same signed, encrypted `PeerMessage` frames through the server as
`RelayData`. The server only moves ciphertext and stamps the authenticated sender.
The relay session key is derived from the static X25519 DH (symmetric, no interactive
handshake), so the fallback path trades forward secrecy for reliable delivery.

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

Each peer is stored in a directory addressed by their identity hash:

```
~/.sechat/peers/<hex(sha256(x25519 ‖ ed25519))>/
    peer.pub        # peer's two public keys (plaintext, 64B)
    chat.db         # encrypted message history (sled)
```

No filesystem metadata leaks the peer's identity beyond the hash.

### 8. Offline Messages

When there is no live session, a message is delivered through the server mailbox:

```
Bob: text -> encrypt with the shared storage_key -> sign
     -> wrap in an ephemeral blob envelope encrypted for Alice
     -> SendBlob(recipient = alice_id) to the server
Server: if Alice is online, push immediately; else store under alice_id
Alice (on connect): decrypt the envelope, verify Bob's signature,
     decrypt with the shared storage_key, store in chat.db, then AckBlob
Server: delete the blob on acknowledgment
```

The server only ever holds an opaque, doubly-encrypted blob addressed to a hash.

### 9. History Synchronization (not implemented)

The P2P wire format reserves `SyncRequest` / `SyncResponse` frames for exchanging
messages missed while offline, but the handler is a placeholder — no synchronization
happens yet. Each device keeps only the history it directly received. This is a
planned feature, not a current one.

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

Each WebSocket connection begins with a signed authentication message carrying both
public keys:

```
{
    pub_key,    // x25519 (identity/address)
    verif,      // ed25519 verifying key
    signature = Ed25519(signing_key, pub_key ‖ verif ‖ timestamp)
}
```

The server verifies the signature with `verif` and rejects timestamps outside a ±30
second window (replay protection). It then derives the routing identity
`id = sha256(pub_key ‖ verif)`. Binding both keys into the identity means a client can
only ever authenticate as the identity that includes its own signing key — it cannot
claim someone else's x25519 address. There are no accounts; the identity lives only
for the connection.

### What the server sees

| Component    | Visible to server                                          | Invisible to server                         |
| ------------ | ---------------------------------------------------------- | ------------------------------------------- |
| Auth         | each connection's identity hash `sha256(x25519 ‖ ed25519)` | the raw keys' owner (no directory of users) |
| Mailbox      | recipient identity hash, encrypted blob, timestamp         | plaintext, and which real person that is    |
| Presence     | rotating token, announced ip:port, timestamp               | which identity a token belongs to           |
| Relay (TURN) | sender + recipient identity hashes, ciphertext, timing     | message contents                            |

The server never sees plaintext. But note: because connections and the mailbox are
keyed by a stable identity hash, and the relay forwards between two such hashes, the
server **can** observe the communication graph (which hash talks to which) for
mailbox and relayed traffic. Direct P2P sessions, once punched, bypass the server
entirely. Presence tokens are per-pair and unlinkable to an identity on their own.

---

## Compromise & Recovery

### Identity compromise

There is no in-band key rotation. If a private key is compromised, recovery is manual:
delete `~/.sechat/`, create a fresh identity, and re-exchange keys out-of-band with
each contact. Because storage keys are derived from identity keys, the old encrypted
history becomes permanently inaccessible once the old identity is gone.

### Identity binding

A peer is stored as both its x25519 and ed25519 keys, and every frame it sends is
verified against that stored verifying key. A peer whose signing key changed would
simply fail verification (its messages are dropped). There is no automatic
"key changed — re-trust?" prompt yet; re-trusting means re-adding the peer with the
new keys, obtained out-of-band.

### Message deletion (purge)

Either party can **purge** a conversation: the initiator wipes its own `chat.db` and
sends a signed `Purge` blob; on receipt the peer verifies it and wipes their copy too.
The contact itself is kept. Delivery of the purge is best-effort — as in any P2P
system there is no way to force deletion on a peer who never comes online to receive it.

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
sled                  embedded key-value store (values encrypted before write)
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

## MVP with both gui and cli

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

Working end to end: identity + password-encrypted key storage, presence, offline
message mailbox, direct P2P (STUN-assisted hole punching) with a TURN-style relay
fallback, at-rest encrypted history, peer aliases, unread indicators, and graceful
shutdown, exposed through both a GUI and a CLI.

Known limitations:

- The cryptographic protocol has **not** been formally reviewed.
- Symmetric-NAT pairs fall back to the relay (no direct path); this is expected.
- The relay fallback uses a static-DH session key, so it has no forward secrecy
  (direct sessions do).
- The relay still learns _who talks to whom_ (as presence already does), though it
  never sees plaintext.
- 1-to-1 only; no group chat, no message sync across devices, no key rotation.

This remains an early-stage research project. Do not use it for sensitive
communication. Contributions, protocol critique, and review are welcome.
