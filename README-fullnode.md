# BTC full node setup with HTTP API

Bitcoin full nodes are unusable as source-of-truth to construct transactions & get UTXOs.
It's possible to make it work for *specific addresses* (after time-consuming re-indexing), but not for *a random address*.

Electrum server solves this problem. It creates extra 1TB of indexes, which allows to fetch info about any address very quickly.
No network access is required for it.

## Flavors of Electrum Server

There are two flavors:

1. [Blockstream fork of Electrs](https://github.com/Blockstream/electrs) (made for esplora). It exposes HTTP API with CORS headers. Recommended.
2. [Original Electrs](https://github.com/romanz/electrs).
   Since it doesn't expose proper HTTP API, we have to make a proxy.
   Use `test/proxy.ts` in the repository as a bridge to electrs TCP.
   The proxy binds to `127.0.0.1`, sends `Access-Control-Allow-Origin: *` for browser tests,
   and supports address, transaction, and block txid lookups.

We support both.

## Requirements

- 64GB RAM, 2.5TB of storage, as per 2026
    - 32GB RAM can work, but needs fine-tuning of electrum server
- 3+ days of sync time
- Bitcoin Core node
    - It must be fully synced (takes 1 day)
    - It must not be pruned
    - It must have tx index: `txindex=1` flag
    - It must have TCP-based RPC API enabled
- Electrum Server node
    - It must be fully synced (takes up to 2 days)
    - The compaction phase can take 24+ hours
    - Monitor the whole process for errors
    - Either Blockstream fork,
    - Or original version by romanz, combined with our HTTP-to-TCP proxy

Security assumptions:

- Bitcoin core can access network using specific ports
- Electrum server doesn't need network and can be firewalled completely
    - It would only connect to local bitcoin core address

- Initial indexing can take a long time. Watch logs, metrics, and DB growth
  before assuming it is stuck.
- If Bitcoin Core is restarted, electrs should reconnect and continue from its
  existing DB. Do not delete either datadir to fix ordinary startup failures.
- Keep public firewall policy closed for Electrum and Bitcoin RPC. If browser
  tests need access, put the service behind a private network or SSH tunnel.


## Installing Bitcoin Core

Bitcoin Core settings:

```ini
server=1
txindex=1
prune=0
listen=1
bind=127.0.0.1:8333
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
whitelist=download@127.0.0.1
maxuploadtarget=512M
maxconnections=14
```

## Installing Electrum Server

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang cmake libclang-dev pkg-config protobuf-compiler curl git

getent group bitcoin >/dev/null || sudo groupadd --system bitcoin
id electrs >/dev/null 2>&1 || sudo useradd --system --user-group --home-dir /var/lib/electrs-blockstream --shell /usr/sbin/nologin electrs
sudo usermod -a -G bitcoin electrs
sudo install -d -o electrs -g electrs -m 0750 /var/lib/electrs-blockstream

sudo install -d -m 0755 /srv/electrs
sudo chown "$(id -u):$(id -g)" /srv/electrs
git clone https://github.com/Blockstream/electrs.git /srv/electrs/blockstream
cd /srv/electrs/blockstream
cargo build --locked --release --bin electrs
sudo install -m 0755 target/release/electrs /usr/local/bin/electrs-blockstream

/usr/local/bin/electrs-blockstream \
  --network bitcoin \
  --daemon-dir /var/lib/bitcoin \
  --blocks-dir /var/lib/bitcoin/blocks \
  --cookie /var/lib/bitcoin/.cookie \
  --daemon-rpc-addr 127.0.0.1:8332 \
  --db-dir /var/lib/electrs-blockstream \
  --electrum-rpc-addr 127.0.0.1:51001 \
  --http-addr 127.0.0.1:3000 \
  --cors '*' \
  --utxos-limit 10000 \
  --electrum-txs-limit 10000 \
  --monitoring-addr 127.0.0.1:4324 \
  --jsonrpc-import
```

This guide uses the following conventional layout:

- Source checkout: `/srv/electrs/blockstream`
- Installed binary: `/usr/local/bin/electrs-blockstream`
- Bitcoin datadir: `/var/lib/bitcoin`
- electrs DB: `/var/lib/electrs-blockstream`
- Service user: `electrs`

The setup this guide is based on built `Electrum Rust Server 0.4.1`. One tested
checkout selected Rust `1.92` through its toolchain file. If the build reports
that `time` or `time-core` needs a newer compiler, install or select a newer
stable Rust toolchain and rerun the same Cargo command.

If Bitcoin Core uses cookie auth, the `electrs` user must be able to read
`/var/lib/bitcoin/.cookie`. One common setup is to run Bitcoin Core with group
`bitcoin`, make the datadir searchable by that group, and keep the cookie
group-readable after Bitcoin starts.

`--cors '*'` is useful for local browser explorers and replay capture tooling.
If a reverse proxy is used, make sure it does not strip CORS headers.
`--utxos-limit 10000` raises the default per-address UTXO lookup ceiling for
developer nodes; keep public services stricter or avoid querying very busy
addresses.
`--electrum-txs-limit 10000` raises the raw Electrum history ceiling so the
test proxy can match the HTTP `/address/:address` and `/address/:address/txs`
endpoints on busy addresses.

### Electrs systemd unit

```ini
[Unit]
Description=Esplora-compatible Bitcoin indexer
After=network-online.target bitcoin.service
Wants=network-online.target

[Service]
User=electrs
Group=electrs
SupplementaryGroups=bitcoin
ExecStart=/usr/local/bin/electrs-blockstream \
  --network bitcoin \
  --daemon-dir /var/lib/bitcoin \
  --blocks-dir /var/lib/bitcoin/blocks \
  --cookie /var/lib/bitcoin/.cookie \
  --daemon-rpc-addr 127.0.0.1:8332 \
  --db-dir /var/lib/electrs-blockstream \
  --electrum-rpc-addr 127.0.0.1:51001 \
  --http-addr 127.0.0.1:3000 \
  --cors * \
  --utxos-limit 10000 \
  --electrum-txs-limit 10000 \
  --monitoring-addr 127.0.0.1:4324 \
  --jsonrpc-import
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/lib/electrs-blockstream /var/lib/bitcoin

[Install]
WantedBy=multi-user.target
```

### Electrs systemd network filter

```ini
# /etc/systemd/system/electrs-blockstream.service.d/network.conf
[Service]
IPAddressDeny=any
IPAddressAllow=127.0.0.0/8
```

Adds a drop-in that prevents the service from connecting to or accepting traffic
from anything except loopback.

If `--electrum-rpc-addr`, `--http-addr`, or `--monitoring-addr` is intentionally
bound to a private management network, add that exact private subnet to
`IPAddressAllow`. Do not add public ranges. Reload systemd and restart electrs
after creating or editing the drop-in:

```bash
sudo systemctl daemon-reload
sudo systemctl restart electrs-blockstream
```

### Alternative: original romanz repo + TCP-to-HTTP proxy

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang cmake cargo rustc librocksdb-dev pkg-config

getent group bitcoin >/dev/null || sudo groupadd --system bitcoin
id electrs >/dev/null 2>&1 || sudo useradd --system --user-group --home-dir /var/lib/electrs-romanz --shell /usr/sbin/nologin electrs
sudo usermod -a -G bitcoin electrs
sudo install -d -o electrs -g electrs -m 0750 /var/lib/electrs-romanz
sudo install -d -o root -g electrs -m 0750 /etc/electrs

sudo install -d -m 0755 /srv/electrs
sudo chown "$(id -u):$(id -g)" /srv/electrs
git clone https://github.com/romanz/electrs.git /srv/electrs/romanz
cd /srv/electrs/romanz
cargo build --locked --release
sudo install -m 0755 target/release/electrs /usr/local/bin/electrs-romanz
```

```toml
network = "bitcoin"
daemon_dir = "/var/lib/bitcoin"
cookie_file = "/var/lib/bitcoin/.cookie"
db_dir = "/var/lib/electrs-romanz"
daemon_rpc_addr = "127.0.0.1:8332"
daemon_p2p_addr = "127.0.0.1:8333"
electrum_rpc_addr = "127.0.0.1:50001"
monitoring_addr = "127.0.0.1:4224"
log_filters = "INFO"
```

```ini
[Unit]
Description=Electrum server backed by Bitcoin Core
After=network-online.target bitcoin.service
Wants=network-online.target

[Service]
User=electrs
Group=electrs
SupplementaryGroups=bitcoin
ExecStart=/usr/local/bin/electrs-romanz --skip-default-conf-files --conf /etc/electrs/romanz.toml
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/lib/electrs-romanz /var/lib/bitcoin

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart electrs-romanz
```

The setup this guide is based on built `romanz/electrs` `v0.11.1`.

### Verification

```bash
curl http://127.0.0.1:3000/blocks/tip/height
curl http://127.0.0.1:3000/fee-estimates
curl -i -H 'Origin: http://example.invalid' http://127.0.0.1:3000/blocks/tip/height
curl http://127.0.0.1:4324/metrics
```

The HTTP API **may not listen until the initial import and RocksDB compaction have finished**. Large full-chain imports can spend hours compacting after block import.

Expected CORS response includes:

```text
access-control-allow-origin: *
```

## Troubleshooting

- `Too many open files`: set `LimitNOFILE=1048576` in the service unit.
- `Too many history entries` from `/address/:address/utxo`: raise
  `--utxos-limit`, for example to `10000`, or avoid popular addresses on public
  endpoints.
- `Too many history entries` from the raw Electrum proxy while HTTP
  `/address/:address` works: raise `--electrum-txs-limit`, for example to
  `10000`. Changing either limit only needs a service restart, not a reindex.
- HTTP port closed during first start: wait for initial import and compaction to
  complete, and watch logs plus metrics.
- JSON-RPC import disconnect messages: check whether block height, DB size, or
  metrics continue moving before restarting.
- Slow browser calls: verify that CORS is present and that the HTTP API is
  reachable over a private network, not the public internet.

## JS usage

```ts
import { EsploraProvider } from '@scure/btc-signer/net.js';
const net = new EsploraProvider(fetch, 'http://127.0.0.1:3000');
const height = await net.height();
const fee = await net.fee(2);
```

### Usage with raw TCP proxy

If only raw Electrum TCP is available, run the dev bridge from this repository:

```bash
node test/proxy.ts --electrum tcp://127.0.0.1:51001 --listen 127.0.0.1:3001 --network mainnet
```

Then point `EsploraProvider` at the bridge URL.

### All API methods

Electrum is JSON-RPC over newline-delimited TCP:

```bash
printf '{"id":0,"method":"server.version","params":["probe","1.4"]}\n' | nc 127.0.0.1 50001
printf '{"id":1,"method":"blockchain.headers.subscribe","params":[]}\n' | nc 127.0.0.1 50001
curl http://127.0.0.1:4224/metrics
```

Full list of API methods:

- `GET /blocks/tip/height`
- `GET /block-height/:height`
- `GET /block/:hash`
- `GET /block/:hash/txids`
- `GET /block/:hash/txs/:start_index`
- `GET /tx/:txid`
- `GET /tx/:txid/hex`
- `GET /address/:address`
- `GET /address/:address/utxo`
- `GET /address/:address/txs`
- `GET /address/:address/txs/chain/:last_txid`
- `GET /fee-estimates`
- `POST /tx`
