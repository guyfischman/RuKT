# Deploying a RuKT log

Runs the server behind Caddy, which obtains and renews a Let's Encrypt
certificate automatically and reverse-proxies gRPC to the log over h2c.

## Ingress

Point DNS at the host in **DNS-only** mode (grey cloud, if the zone is on
Cloudflare) and let Caddy terminate TLS. Cloudflare Tunnel is deliberately not
used because of [cloudflare/cloudflared#1641](https://github.com/cloudflare/cloudflared/issues/1641).

## Run

```bash
export KT_GOOD_HOST=good.kt.example.com
export ACME_EMAIL=you@example.com
docker compose up -d --build
```

Ports 80 and 443 must be reachable from the internet: 80 for the ACME HTTP-01
challenge, 443 for gRPC.

## Publish the trust root

The log writes its public config to `/data/config.json` on every start. Clients
must be handed it **out of band** — never fetched from the log they are
verifying:

```bash
docker compose exec good cat /data/config.json
```

Serve that file from somewhere independent of the log (R2, Pages, a gist) and
give working-group members the URL. Clients then:

```rust
let config = PublicConfig::from_json(&std::fs::read_to_string("config.json")?)?;
let mut client = KtClient::connect("https://good.kt.example.com".into(), config).await?;
```

## Log parameters are immutable

The cipher suite, deployment mode, and `KT_MAX_AHEAD` / `KT_MAX_BEHIND` /
`KT_MONITORING_WINDOW` are all signed into every tree head. Changing them on an
existing volume invalidates every head already published, and clients will
report a tree-head signature failure. Choose them before the first start; to
change one afterwards, wipe the volume and republish `config.json`.

`KT_EPOCH_INTERVAL_SECS` is *not* signed and can be changed freely. It
re-publishes the head on a timer so an idle log stays inside clients'
`KT_MAX_BEHIND` freshness window; keep it well below that value.

## State

The signing key, VRF key, and log live in the `good-data` volume. Losing it
means a new log identity and a new `config.json` for everyone.
