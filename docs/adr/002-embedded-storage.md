# ADR-002: Embedded Storage Engine Selection (sled vs SQLite)

## Status

Accepted

## Context

sechat requires persistent local storage for two purposes:

1. **Conversation history** — append-only encrypted message log per peer, addressed by `sha256(peer_pub)`
2. **Server-side mailbox** — store-and-forward encrypted blobs addressed to `sha256(recipient_pub)`, deleted on acknowledgment

Both use cases share the same access pattern: key-based lookup, append writes, occasional range scans by timestamp, no relational joins, no cross-entity transactions.

The two realistic candidates for an embedded Rust storage engine are **sled** and **SQLite** (via `rusqlite`).

## Decision

Use **sled** for both client conversation storage and server mailbox storage.

## Rationale

**Access pattern alignment**

sechat's data model is a key-value store: messages live under a key derived from peer identity, blobs live under a recipient hash. There are no joins, no foreign keys, no relational queries. sled is a native key-value store — the data model maps directly without an impedance mismatch. Using SQLite would mean wrapping a relational engine around a problem that is not relational.

**Rust-native API**

sled is written in Rust and exposes an idiomatic async-compatible API. There are no FFI boundaries, no C library linked at build time, no risk of threading issues crossing the FFI layer. `rusqlite` wraps the SQLite C library — functional, but adds build complexity and a foreign dependency.

**Transactional append-only writes**

sled supports atomic batch writes and compare-and-swap operations natively. For an append-only chat log, this is sufficient. The absence of full ACID transaction support (sled does not guarantee durability on power loss in all configurations) is acceptable because conversation history is a best-effort local cache — losing the last few messages on a crash is tolerable, not a correctness failure.

**Zero-configuration schema**

sled requires no schema definition, no migrations, no query language. For a storage model that maps peer hashes to encrypted blobs, this is an advantage — the storage layer stays thin and auditable.

## Consequences

**Positive**

- No FFI, no C dependency, simpler build
- Data model maps directly to key-value without translation layer
- Idiomatic Rust API, works with tokio
- No schema migrations to manage

**Negative**

- sled is not production-stable (0.x versioning as of writing) — the API may change and durability guarantees are weaker than SQLite's WAL mode
- No query language — if future requirements need filtering messages by content, date range, or type, implementing scan logic manually is more work than a SQL `WHERE` clause
- sled's tree compaction and space reclamation are less predictable than SQLite's `VACUUM`
- Smaller ecosystem, fewer debugging tools compared to SQLite (no equivalent of DB Browser for SQLite)

## Alternatives Considered

**SQLite via rusqlite**

- Battle-tested, used in production by Firefox, Android, and countless embedded systems
- Full ACID guarantees with WAL mode
- Rich query capabilities via SQL
- Rejected because: relational model is unnecessary overhead for key-value access patterns; FFI dependency complicates the build and security audit surface; schema migrations add operational complexity for a local-only store

**SQLite via sqlx (async)**

- Same trade-offs as rusqlite with async support
- Rejected for the same reasons as rusqlite; async wrapper adds another abstraction layer with no benefit for this use case

**Redb**

- Newer Rust-native embedded key-value store, stronger durability guarantees than sled, stable API
- Not chosen at project start due to maturity concerns at the time; worth reconsidering as an upgrade path if sled's stability becomes a problem in practice

## Open Questions

- If full-text search over message history becomes a requirement (e.g. searching past conversations), SQLite with FTS5 would be significantly easier to implement than a manual scan over sled trees. This would be a reason to revisit this decision.
- sled's 1.0 release (in progress at time of writing) may resolve the durability and API stability concerns. The decision should be reviewed once sled reaches stable.
