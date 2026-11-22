# testpeer

Userspace WireGuard test peer for WGEX (ticket P0-08). Test infrastructure only; never shipped.

It runs wireguard-go (pinned at `b3bc704ef0ee21a36298601a9e1e5ff90377ac52`, the engine's pin) on a gVisor netstack (`tun/netstack`). It needs no privileges: no utun, routes, pf or launchd. It binds only ordinary UDP and TCP sockets: the WireGuard port and, when asked, the marker listener. All in-tunnel services live inside the netstack, not on the host.

## Build and test

```sh
cd Tools/testpeer
GOTOOLCHAIN=local GOFLAGS=-mod=mod go test ./...   # about 10 s; in-process netstack clients over loopback
go vet ./... && staticcheck ./...
go build -o "$CLEAN_DEV_BUILDS/testpeer/testpeer" .
```

## Usage

```sh
just testpeer -- --help    # flag list; `just testpeer -- <flags>` runs it via `go run`

testpeer --key-file testdata/server.key --peers 2 \
  --public-address 192.168.1.20 --out-dir "$TMPDIR/testpeer" \
  --marker-listen 192.168.1.20:8088

# Fixed keys from the shared fixtures: the client side (an engine test, the
# lab VM) holds Tests/Fixtures/keys/client1.key, so nothing is generated.
testpeer --key-file ../../Tests/Fixtures/keys/server.key \
  --client-key-file ../../Tests/Fixtures/keys/client1.pub
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen addr:port` | `0.0.0.0:51820` | WireGuard UDP. Repeatable; every address must use the same port. A single `0.0.0.0` (or `::`) uses `conn.NewDefaultBind()`, which always opens IPv4 and IPv6 wildcard sockets; without `--ipv6` the chaos wrapper drops IPv6-sourced datagrams. Specific addresses (LAN or loopback) use a small per-address bind; with `--ipv6` and no IPv6 address listed, `[::]` is added. |
| `--key-file path` | none | Server private key: a bare base64 key (`wg genkey` output) or a wg-quick `PrivateKey = ...` line. Blank lines and lines starting with `#` or `;` are skipped, so the commented fixture files in `Tests/Fixtures/keys/` load as they are. Without it an ephemeral key is generated. |
| `--client-key-file path` | none | A fixed client **public** key (a bare base64 key such as `Tests/Fixtures/keys/client1.pub`, or a `PublicKey = ...` line; same comment rules). Repeatable. Each file adds a peer `fixed-N` that takes the next inner addresses before any generated `--peers` (so `client1.pub` gets `10.77.0.2`). No `.conf` or QR is written for it: the test client already holds the matching private key. It is logged as a `client` event with its public key only. |
| `--print-keys` | off | Prints secrets to **stderr**: the server private key, each client `.conf` and a terminal QR. Without this flag, no secret is printed or logged. |
| `--peers n` | `0` | Generates n client key pairs (`client-1` ...), addressed from the inner ranges. |
| `--public-address ip` | none | Endpoint host written into client configs. Required when `--peers` is above 0. |
| `--out-dir dir` | none | Writes `client-N.conf` and `client-N.png` (QR of the `.conf`), mode 0600. `--peers` needs either `--out-dir` or `--print-keys`. |
| `--inner-cidr` | `10.77.0.0/24` | The server takes the first host (`10.77.0.1`) and clients follow. |
| `--ipv6` | off | Adds the ULA range `--inner-cidr6` (default `fd77:6765:7800::/64`, server `::1`) and accepts WireGuard over IPv6. |
| `--mtu` | `1420` | Tunnel MTU, also written into the client configs. |
| `--client-allowed-ips` | `0.0.0.0/0` (and `::/0` with `--ipv6`) | AllowedIPs in the client configs. |
| `--marker-listen ip:port` | off | Clear-text marker listener; repeatable (give the LAN IPv4 and IPv6 addresses). Must be a specific address. |
| `--marker-dns-port` | `5354` | Marker DNS port on each marker IP; `-1` disables it. |
| `--log-level` | `info` | `debug` adds wireguard-go's verbose log. |
| `--json` | `true` | JSON lines on stdout; `--json=false` gives logfmt. |
| `--counters-interval` | `5s` | Period of `counters` events. |

Generated client configs route everything into the tunnel by default. **The peer is not a router**: traffic to any address other than the server's inner addresses is silently discarded inside the netstack.

## In-tunnel services (server `10.77.0.1`, and `fd77:6765:7800::1` with `--ipv6`)

- HTTP on ports 80 and 8088:
  - `/ip`: the client's tunnel source address.
  - `/echo`: echoes the request body as a full-duplex stream, so streaming uploads work.
  - `/big?bytes=N`: N pseudo-random bytes (ChaCha8), with a 2 GiB cap.
  - `/delay?ms=N`: replies after N ms, with a cap of 120000.
  - `/leak/<nonce>`: records an `in_tunnel` marker.
- DNS over UDP on port 53 and on the marker DNS port (5354 by default):
  - `*.test.wgex` returns the server address.
  - `<nonce>.leak.wgex.test` records an `in_tunnel` marker and returns the server address.
  - Other names return NXDOMAIN.
  - TTL is 0, and every query is logged as `dns_query`.
- UDP echo on port 7. A `WGEXLEAK <nonce>` payload is also recorded as an `in_tunnel` marker.
- UDP markers on port 8088.
- ICMP and ICMPv6 echo: the gVisor stack answers these itself. `TestTunnelServices` checks this from a netstack client.

## Leak-detection model (receiver-based)

`Tools/leakprobe` on the device or VM under test sends marked traffic to two targets. The first is the server's in-tunnel address. The second is the marker listener's LAN address, both IPv4 and IPv6, which is outside the tunnel. The marked traffic is:

- DNS queries for `<nonce>.leak.wgex.test`
- HTTP `GET /leak/<nonce>`
- UDP datagrams `WGEXLEAK <nonce>`

The peer is the receiver and the judge:

- A marker that arrives through WireGuard is logged as `{"event":"marker","scope":"in_tunnel",...}` at info level. The log line names the peer.
- A marker that arrives on `--marker-listen` (HTTP or UDP on `ip:port`, DNS on `ip:<marker-dns-port>`) did not go through the tunnel. It is logged as `{"event":"marker","scope":"outside_tunnel",...}` at **warn** level, so it survives `--log-level warn`. **That line is the leak evidence.**
- The resolver is dual-homed: the same names are answered in-tunnel and on each marker IP. The marker resolver answers with its own IP, so a leaked lookup leads to a leaked HTTP request that is caught too.
- In `protected`, only `in_tunnel` markers may appear. Any `outside_tunnel` marker means a leak.

The default marker DNS port is 5354 rather than 5353. On macOS, mDNSResponder holds `*:5353`, and sharing that port would need `SO_REUSEPORT` and would capture unicast mDNS. Pass `--marker-dns-port 5353` on hosts where that port is free.

## Event log

stdout carries one JSON object per line with `ts`, `level` and `event`. The events are:

- `started`, `client`, `marker_listener`
- `handshake`: one each time a peer completes a handshake.
- `endpoint_change`: `old` and `new`.
- `counters`: per peer, every `--counters-interval`.
- `chaos_counters`
- `dns_query`, `marker`
- `chaos_config`, `chaos_drop`: the first drop per rule and source; later drops are counted.
- `chaos_drop_after_active`, `deprecated_flag`
- `wireguard` (debug), `wireguard_error`
- `fatal`, `stopping`

Events carry public keys only. Peer state comes from parsing `IpcGet`. That output includes the private key, which is discarded and never logged.

## Chaos (WireGuard UDP only)

A `conn.Bind` wrapper around the inner bind (`conn.NewDefaultBind()` for wildcard listens) applies the chaos flags:

- `--drop-udp-from cidr` (repeatable) drops inbound datagrams whose UDP source is inside the CIDR.
- `--allow-udp-only-from ip|cidr` drops inbound datagrams from every other source.
- `--loss pct` is random loss applied independently to inbound and outbound datagrams. 100 means no handshake.
- `--latency ms` delays outbound datagrams through a FIFO queue, adding about `ms` to the round trip.
- `--drop-udp-after seconds` is **deprecated**: after the delay, it drops all inbound WireGuard UDP from every source.

The source filters act on the UDP source address. When traffic reaches the peer through a relay (phase 6: sing-box forwarding to the peer), the source is the relay. So `--drop-udp-from <client LAN CIDR>` or `--allow-udp-only-from <relay ip>` cuts the direct path and leaves the relayed path alone. `--drop-udp-after` hits the relayed path too, so it cannot test relay fallback. Use the source-scoped flags for that.

## Test key fixture

`testdata/server.key` is a **throwaway test fixture**: a private key published in the repository on purpose, used only by these tests, protecting nothing. Never use it on a real device or server, and never replace it with a key that is in use anywhere. Its comment header says the same. It is key-shaped, so `Tools/lint/check-no-secrets-in-strings.sh` lists `Tools/testpeer/testdata/` among its fixture exclusions (the scan reads only Swift, Go and YAML sources today, so this guards a future widening). gitleaks does not report it, so `.gitleaks.toml` has no entry for it.

Shared fixtures for other components live in `Tests/Fixtures/keys/` (P0-19); `--key-file` and `--client-key-file` accept their format (a `#` header line, then the key). The unit tests load `server.key`, `client1.key` and `client1.pub` from there and complete a handshake with the fixed client key (`fixedclient_test.go`).

## Dependencies (all permissive)

- golang.zx2c4.com/wireguard: MIT
- gvisor.dev/gvisor: Apache-2.0, transitive and test-only
- github.com/skip2/go-qrcode: MIT. It generates both the PNG and the terminal QR.
- golang.org/x/net (`dns/dnsmessage`), x/crypto, x/sys and x/time: BSD-3-Clause
- github.com/google/btree: Apache-2.0
