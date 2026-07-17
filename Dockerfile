FROM rust:1-bookworm AS builder

# libprotobuf-dev supplies the well-known .proto files that key_transparency.proto imports.
RUN apt-get update && apt-get install -y --no-install-recommends \
      protobuf-compiler libprotobuf-dev clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
COPY benches ./benches
COPY examples ./examples

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin rukt && cp target/release/rukt /rukt

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home rukt \
    && mkdir -p /data && chown rukt:rukt /data

COPY --from=builder /rukt /usr/local/bin/rukt

USER rukt
VOLUME ["/data"]
EXPOSE 8081

ENV KT_DATA_DIR=/data \
    KT_LISTEN=0.0.0.0:8081

ENTRYPOINT ["/usr/local/bin/rukt"]
