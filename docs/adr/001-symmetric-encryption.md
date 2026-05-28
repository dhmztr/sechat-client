# ADR-001: Symmetric Encryption Algorithm Selection

## Status

Accepted

## Context

sechat requires an AEAD (Authenticated Encryption with Associated Data) cipher for three distinct use cases:

1. **Message encryption** — encrypting individual messages over a P2P session
2. **At-rest encryption** — encrypting the identity keypair on disk (`identity.key`)
3. **Storage encryption** — encrypting conversation history (`chat.db` per peer)

All three require confidentiality and integrity in a single primitive. The two realistic candidates for a Rust project with modern security requirements are **ChaCha20-Poly1305** and **AES-256-GCM**.

The target platform is a desktop client running on Linux, macOS, and Windows — including hardware without AES-NI acceleration (older machines, some ARM devices, embedded systems).

## Decision

Use **ChaCha20-Poly1305** for all symmetric encryption in sechat.

## Rationale

**Performance without hardware acceleration**

AES-256-GCM depends on AES-NI for competitive performance. Without it, software AES is significantly slower and the timing characteristics open potential side-channel windows. ChaCha20-Poly1305 is designed for software implementation — it performs consistently across all platforms regardless of hardware support. For a desktop chat client targeting diverse hardware, this matters.

**Nonce safety**

AES-256-GCM uses a 96-bit nonce. At high message volumes, the probability of a random nonce collision becomes non-negligible before key rotation occurs. ChaCha20-Poly1305 also uses a 96-bit nonce, but sechat uses counter-derived nonces (`base_nonce XOR counter_n`) within a session, making collisions impossible as long as the counter is monotonic — which is guaranteed by the session model.

**Implementation simplicity and auditability**

The `chacha20poly1305` crate in the Rust ecosystem is well-maintained, minimal in scope, and straightforward to audit. It has no dependency on OpenSSL or system crypto libraries, which simplifies builds and removes a class of supply-chain risk.

**Established security track record**

ChaCha20-Poly1305 was designed by Daniel J. Bernstein, is specified in RFC 8439, and is used in TLS 1.3, WireGuard, and Signal. It has received extensive cryptanalysis and is considered at least as secure as AES-256-GCM for practical purposes.

## Consequences

**Positive**

- Consistent performance across all target platforms
- No dependency on AES-NI or OpenSSL
- Deterministic nonce scheme eliminates nonce reuse risk within a session
- Simpler build pipeline (no system crypto library linkage)

**Negative**

- Not FIPS 140-2 approved — rules out deployment in US federal government environments without a separate compliance path. This is acceptable for sechat's threat model (personal communication tool), but would be a blocker if the protocol were adopted in a regulated enterprise context.
- AES hardware acceleration on modern x86 would be faster for bulk encryption of large stored histories. For typical chat message sizes this difference is negligible.

## Alternatives Considered

**AES-256-GCM**

- FIPS 140-2 approved
- Hardware-accelerated on most modern x86/x64 processors
- Rejected because: software fallback is slower and has worse timing properties; nonce management requires more care at scale; FIPS compliance is not a requirement for this project

**AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)**

- Older construction, still secure when implemented correctly
- Rejected because: requires two separate primitives and careful ordering; AEAD APIs are strictly simpler and harder to misuse; no advantage over ChaCha20-Poly1305 for this use case

**XChaCha20-Poly1305**

- Extended 192-bit nonce variant — safe for random nonce generation even at high volume
- Not chosen because: sechat uses counter-derived nonces, making the extended nonce unnecessary; 96-bit nonce with counter scheme achieves the same safety property more explicitly
- Worth reconsidering if the nonce scheme changes in a future revision
