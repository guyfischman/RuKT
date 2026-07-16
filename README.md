# RuKT

A Key Transparency implementation in Rust, conformant to
**[draft-ietf-keytrans-protocol-05](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/)**
and **[draft-ietf-keytrans-architecture-09](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/)**
(both vendored under [`docs/spec/`](docs/spec/)).

Key Transparency is a verifiable, append-only log that maps user identifiers
(*labels*) to values such as public keys. Every response the log gives is
accompanied by a cryptographic proof, so a client can detect a server that
serves a forged key, hides a version, rolls back its history, or shows different
users different views — without trusting the server.

RuKT implements the participant roles:

| Role | Type | Entry point |
|------|------|-------------|
| **Transparency Log** (server) | gRPC service | `KeyTransparencyImpl` ([`src/service.rs`](src/service.rs)) |
| **Client** | verifying library — search, update, monitoring, and offline credential verification | `KtClient` ([`src/client/core.rs`](src/client/core.rs)) |
| **Third-Party Auditor** | log verifier | `KtAuditor` ([`src/client/auditor.rs`](src/client/auditor.rs)) |

## What it does

- **Full client-side verification.** The client independently reconstructs the
  log-tree root from every proof and checks the tree-head signature. Nothing a
  response claims is trusted: VRF outputs, commitments, prefix-tree roots, log
  roots, timestamps, and signatures are all verified. Tampering with any field
  is rejected.
- **Linearizable, fork-evident.** Clients persist their verified view and require
  each new response to prove it extends the last one (`last`, retained
  subtrees). A rolled-back or divergent-log head fails verification. Peers can
  exchange signed heads and recent distinguished-head root values over an
  out-of-band channel to detect a server that partitions its users; a
  double-signing server yields self-contained, third-party-verifiable evidence.
- **The full protocol-05 operation set:**
  - *Search* — greatest-version or a specific version of a label.
  - *Update* — compare-and-swap on the label's greatest version, so concurrent
    writers can't fork a label's history; a behind client is transparently
    caught up on existing versions.
  - *Contact Monitor / Owner Initialization / Owner Monitoring* — the split
    monitoring paths (§8.2/§8.3), replayed and verified client-side.
  - *Distinguished* — walk the recent distinguished heads for fork detection.
  - *Credentials* — standard and provisional credentials plus `CredentialUpdate`,
    verified offline by a recipient without contacting the log.
- **Deployment modes.** Contact Monitoring and Third-Party Auditing are
  implemented; in auditing mode the client verifies the auditor's signed head
  (including a lagging auditor's sub-root) against its own reconstruction, and
  an auditor can bootstrap mid-history. Third-Party Management is out of scope.
- **Deployment obligations from the architecture draft.** A pluggable access
  policy gates Search and Update while monitoring stays unconditionally served;
  values and commitment openings are independently deletable for erasure, and
  expired non-greatest versions can be pruned by maximum lifetime.
- **Cipher suites.** `KT_128_SHA256_ED25519` (Ed25519 + ECVRF-EDWARDS25519-SHA512-TAI)
  and `KT_128_SHA256_P256`.
- **Storage.** Persistent RocksDB with tuned write throughput (large memtables,
  parallel background jobs, batched writes) and a `DashMap` in-memory cache over
  hot prefix-tree nodes.
- **Throughput.** The update batcher pipelines work into four phases —
  sequential versioning, parallel VRF/commitment crypto (`spawn_blocking`),
  sequential Merkle append, and parallel proof generation — dropping the write
  lock early so proofs assemble concurrently. [`src/bulk.rs`](src/bulk.rs) builds
  large trees offline via `rayon` and SST ingestion.

## Prerequisites

- **Rust & Cargo** (edition 2024): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Protobuf compiler** (`protoc`): `brew install protobuf` / `sudo apt install protobuf-compiler`
- **Clang/LLVM** (for RocksDB): `xcode-select --install` / `sudo apt install build-essential clang libclang-dev`

## Build

```bash
cargo build --release
```

## Running the server

```bash
cargo run
```

The server listens on `0.0.0.0:8081` in Contact Monitoring mode. On each start it
**generates fresh keys** and prints them, then serves from a clean `./kt_data`:

```text
=== SERVER KEYS (COPY THESE TO CLIENT) ===
SIG_KEY: <hex>
VRF_KEY: <hex>
==========================================
Key Transparency Server listening on 0.0.0.0:8081
```

Because the keys are ephemeral, a verifying client must be told the server's
public keys out of band — that is the trust root the whole protocol rests on. In
a real deployment the log's configuration (cipher suite, keys, mode parameters)
is pre-distributed over a trustworthy channel;
`PublicConfig::to_json`/`from_json` provides that distribution format.

## Client demo

With the server running, paste its printed `SIG_KEY` and `VRF_KEY` into
[`examples/client_demo.rs`](examples/client_demo.rs), then:

```bash
cargo run --example client_demo
```

```text
Connected to Key Transparency Server
Registering user 'bob'...
Update successful. New Tree Size: 1
Searching for user 'bob'...
Verified Value: "bob_pk_v1"
```

## Using the client library

`KtClient` performs the RPC and the verification together; a call returns only
if the response's proof checks out.

```rust
use rukt::client::KtClient;

let mut client = KtClient::connect(uri, public_config).await?;
client.persist_to("client-state.json")?;  // durable, fork-evident state

client.update(b"alice".to_vec(), b"alice_pk".to_vec()).await?;
let resp = client.search(b"alice".to_vec(), None).await?;   // verified greatest-version search
let value = resp.value.unwrap().value;

client.contact_monitor(b"alice".to_vec()).await?;           // discharge monitoring obligations

// offline credentials: the issuer hands `cred` to a recipient out of band
let cred = client.get_credential(b"alice".to_vec()).await?;
recipient.distinguished(None).await?;                       // learn recent distinguished heads
recipient.verify_credential(&cred)?;                        // verified without contacting the log
```

## Testing

```bash
cargo test --workspace --lib --bins --tests --examples
```

The suite covers each operation client-verified in both deployment modes,
per-field adversarial rejection (a tampered value, opening, ladder, commitment,
timestamp, root, or signature is refused), cross-operation state continuity
across restarts, and fork/rollback rejection.

Formatting and lints are enforced as blocking CI gates:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Interop vectors

Deterministic known-answer vectors for the hashed and signed byte formats
(commitment, VRF, tree hashing, tree-head TBS) are pinned in
[`src/integration/interop_vectors.rs`](src/integration/interop_vectors.rs) and
mirrored, with documented inputs and spec-section anchors, in
[`docs/spec/interop-vectors.json`](docs/spec/interop-vectors.json) for
cross-implementation comparison.

## Benchmarks

```bash
cargo bench
```

Criterion benchmarks ([`benches/kt_benchmarks.rs`](benches/kt_benchmarks.rs))
populate large trees via `src/bulk.rs` and measure search, monitor, and update
at scale, using RocksDB checkpointing so each iteration starts from identical
state.

## Layout

```
proto/            gRPC + wire message definitions (protocol-05)
src/service.rs    gRPC server, deployment-mode wiring, access policy
src/tree/         log tree, prefix tree, traversals, credentials, pruning
src/client/       KtClient (verifying), KtAuditor, offline verifier, gossip
src/crypto/       commitments, VRF, signatures, TLS presentation encoding
src/bulk.rs       offline bulk tree population
docs/spec/        vendored IETF drafts and interop vectors
```
