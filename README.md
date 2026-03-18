# RuKT

Key Transparency (KT) server implementation in Rust. We attempt conformance to **[draft-ietf-keytrans-protocol-03](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/)**.

This server implements a verifiable, append-only log that maps user identifiers (labels) to public keys (values), allowing users to audibly detect unauthorized key changes.

## Features

*   **Protocol Compliance:** Full implementation of Draft-03, including Log Tree, Prefix Tree, and Combined Tree proofs.
*   **Crypto Suites:** Support for `KT_128_SHA256_ED25519` (Ed25519 + ECVRF-EDWARDS25519-SHA512-TAI) and P-256.
*   **Storage:** Persistent storage using **RocksDB** with tuned write throughput (large memtables, parallel background jobs, batched writes).
*   **Privacy:** Randomized VRF proofs to prevent traffic correlation and "deletable openings" for Right-to-be-Forgotten compliance.
*   **gRPC API:** High-performance gRPC interface via `tonic`.
*   **Concurrent Batch Processing:** The batcher pipelines work into four phases — sequential versioning, parallel VRF/commitment cryptography (`spawn_blocking`), sequential Merkle appends, and parallel proof generation — using an `RwLock` to allow concurrent reads during proof assembly.
*   **Prefix Tree Caching:** A `DashMap`-based in-memory node cache eliminates repeated RocksDB reads and protobuf deserialization on hot prefix tree nodes.
*   **Bulk Population:** Utilities in `src/bulk.rs` for building large trees efficiently via SST file ingestion and RocksDB checkpointing, with parallelized cryptography via `rayon`.

## Prerequisites

Before building, ensure you have the following installed:

1.  **Rust & Cargo:**
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2.  **Protobuf Compiler (`protoc`):**
    *   **macOS:** `brew install protobuf`
    *   **Ubuntu/Debian:** `sudo apt install protobuf-compiler`
3.  **Clang/LLVM (Required for RocksDB):**
    *   **macOS:** Included with Xcode command line tools (`xcode-select --install`).
    *   **Ubuntu/Debian:** `sudo apt install build-essential clang libclang-dev`

## Building and Running

1.  **Clone and Build:**
    ```bash
    git clone <your-repo-url>
    cd rukt
    cargo build --release
    ```

2.  **Run the Server:**
    ```bash
    cargo run
    ```
    You should see:
    ```text
    Key Transparency Server listening on 0.0.0.0:8080
    ```

    > **⚠️ Important Note:** By default, this implementation generates **new random cryptographic keys** every time it starts.

## Usage

### 1. Start the Server

Run the server and **keep the terminal open**.

```bash
cargo run
```

You will see output containing cryptographic keys. **Copy these keys**; you will need them for the client to verify proofs.

```text
=== SERVER KEYS (COPY THESE TO CLIENT) ===
SIG_KEY: <hex_string_A>
VRF_KEY: <hex_string_B>
==========================================
Key Transparency Server listening on 0.0.0.0:8080
```

### 2. Configure the Client

Open `examples/client_demo.rs` in your editor. Replace the placeholder strings with the keys you copied from the server output:

```rust
// examples/client_demo.rs

// ...
async fn main() -> anyhow::Result<()> {
    // PASTE KEYS FROM SERVER OUTPUT HERE
    let server_sig_hex = "<PASTE_SIG_KEY_HERE>";
    let server_vrf_hex = "<PASTE_VRF_KEY_HERE>";
    // ...
}
```

> **Why is this necessary?**
> This implementation generates new random cryptographic keys every time the server starts. The client must know these specific public keys to cryptographically verify that the server's responses (Merkle proofs and VRF outputs) are authentic.

### 3. Run the Client Demo

Once the keys are pasted, run the example client in a new terminal window:

```bash
cargo run --example client_demo
```

**Expected Output:**
```text
Connecting with trusted keys...
Connected to Key Transparency Server
Registering user 'bob'...
Update successful. New Tree Size: 1
Searching for user 'bob'...
Verified Value: "bob_pk_v1"
```

### 4. Manual API Check (Optional)

You can also inspect the server status using `grpcurl` to confirm the tree size increased after running the client demo.

```bash
grpcurl -plaintext -emit-defaults \
    -import-path proto \
    -proto key_transparency.proto \
    0.0.0.0:8080 kt.KeyTransparencyService/TreeSize
```

## Benchmarks

Criterion benchmarks live in `benches/kt_benchmarks.rs`. Run them with:

```bash
cargo bench
```

The benchmark suite uses `src/bulk.rs` to rapidly populate large trees (bypassing the gRPC/batcher path) and then measures operations like search, monitor, and update at scale. RocksDB checkpointing is used to snapshot a populated tree so each benchmark iteration starts from identical state.