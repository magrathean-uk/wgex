# Engine

The WGEX engine is a Go module (`Engine/go`, module
`github.com/magrathean-uk/wgex/engine`) around the userspace WireGuard
implementation `golang.zx2c4.com/wireguard`, pinned at commit
`b3bc704ef0ee21a36298601a9e1e5ff90377ac52` (pseudo-version
`v0.0.0-20261024220952-b3bc704ef0ee`). It is compiled into C archives and
packaged as `Packages/WGEXEngine/Binary/WGEXEngine.xcframework`, which Swift
imports as the Clang module `CWGEXEngine`.

## Layout

| Path | Contents |
|---|---|
| `go/go.mod`, `go/go.sum` | Module, `go 1.27`, `toolchain go1.27.3`, wireguard-go pin |
| `go/vendor/` | Every dependency, committed; builds never touch the network |
| `go/bridge/` | `package main` (required by `-buildmode=c-archive`): one-line `//export wgex_*` wrappers |
| `go/bridge/wgex.h`, `go/bridge/module.modulemap` | Hand-written header and module map (`CWGEXEngine`); the header cgo generates is discarded |
| `go/cabi/` | C-facing layer shared by the bridge and test support: handle registry (the only global), process settings, `wgex_create_params` decoding, callback trampolines |
| `go/engine/` | `Engine` (device, tun, SwitchBind, UAPI validation, public statistics, health events, callback dispatcher) and the memory governor |
| `go/transport/` | `SwitchBind`, the only `conn.Bind` given to `device.NewDevice`, and the `udp` inner transport |
| `go/tun/` | tun_kind 0 (NE utun descriptor), 1 (packet descriptor), 2 (root `utun` creation) and the iOS/tvOS utun descriptor scan |
| `go/resolver/` | UnderlayResolver DNS client behind `wgex_resolve` |
| `go/internal/abicheck/` | Header-versus-`//export` comparison used by the bridge and test-support tests |
| `go/testsupport/` | `//go:build wgextest` only: `wgex_test_*` exports (netstack pairs, packet-descriptor echo), header `wgex_test.h`, module `CWGEXEngineTest` |
| `scripts/build-xcframework.sh` | Production XCFramework (`just engine`) |
| `scripts/verify-slices.sh` | Archive checks, run by the build and usable on its own |
| `scripts/build-test-support.sh` | Test-support XCFramework (`just engine-test`) |
| `scripts/smoke-macos.sh` | Links Swift against the macOS slice and prints `wgex_build_info()` |
| `scripts/lib.sh` | Shared helpers (sourced) |

## C ABI (P1-01)

`wgex.h` declares the full ABI of 02-architecture §6.2 plus `wgex_resolve`
(§7.5); `bridge/abi_test.go` fails if the header and the `//export` set
differ, and every packaged slice exports exactly those 18 symbols.

| Function | Behaviour |
|---|---|
| `wgex_configure_process` | Memory limit, GC percent, queue profile (256-deep queues and pools under `GOOS=ios`; constants on macOS). Applied at once, only before the first `wgex_create`; an identical repeat returns `WGEX_OK`, different values or a call after a create return `WGEX_ESTATE`. |
| `wgex_create` | `tun_kind` 0: NE utun descriptor through `tun.CreateTUNFromFile`, `mtu` must be 0 (`WGEX_EINVAL` otherwise). 1: packet descriptor (`tun/packetfd.go`). 2: `tun.CreateTUN` (root; not exercised by tests). The descriptor is duplicated and set non-blocking; the caller keeps its own. `transport_json` NULL or `{"kind":"udp"}`; anything else `WGEX_EINVAL`. The device starts down. |
| `wgex_set_config` | Full replace: the document must contain `private_key`, `listen_port`, `replace_peers=true` and only known keys (`WGEX_EINVAL` before wireguard-go sees it). Read through a `bytes.Reader` over the caller's memory, never a Go string in WGEX code. On an `IpcSetOperation` failure the last good document is re-applied (`WGEX_ECONFIG`, device running); with no good document, or if re-applying fails, the device is closed and only `wgex_destroy` remains useful. The engine's copy of the last good document is wiped when superseded and on destroy. |
| `wgex_update_endpoints` | Only `public_key`, `update_only=true` (directly after each key) and one literal `endpoint`; sessions are kept. |
| `wgex_up`, `wgex_down` | `device.Up` / `device.Down`. |
| `wgex_destroy` | Idempotent. Returns once no callback of the engine is in flight. Called from inside a callback (detected with a C thread-local depth counter set around every callback), it starts the teardown and returns `WGEX_OK` at once; no further callback starts after the current one returns. |
| `wgex_bump_sockets` | Returns at once. A background attempt sets the new interface indexes and calls `BindUpdate` up to 10 times, 500 ms apart, then `SendKeepalivesToPeersWithCurrentKeypair`; the selected listen port is retained across failed opens; a new call or destroy cancels it. Outcome: engine event `socketsBumped`. |
| `wgex_set_transport` | `{"kind":"udp"}` only: udp→udp rebinds the sockets on the same port with `BindUpdate` and keeps sessions. Other kinds `WGEX_EINVAL` until phase 6. |
| `wgex_force_handshake` | Per peer (keys from `IpcGetOperation`, peers through `LookupPeer`): `ExpireCurrentKeypairs` then `SendHandshakeInitiation(false)`. Peers and roamed endpoints are kept. |
| `wgex_find_utun_fd` | `GOOS=ios`: scans descriptors 0...1024 with `getpeername` and `CTLIOCGINFO` for `com.apple.net.utun_control`. Always -1 on macOS. |
| `wgex_public_stats_json` | `{interface_name, listen_port, sampled_at, peers:[{public_key (base64), endpoint, last_handshake_time (RFC 3339), rx_bytes, tx_bytes, persistent_keepalive_interval}]}`. The `IpcGetOperation` output is parsed in place by an `io.Writer`; `private_key` and `preshared_key` lines are skipped without being copied. Free with `wgex_free`. |
| `wgex_tun_name` | Valid until destroy. |
| `wgex_free_os_memory` | `debug.FreeOSMemory`. |
| `wgex_resolve` | A and AAAA over UDP with TCP fallback on truncation, from sockets bound with `IP_BOUND_IF` / `IPV6_BOUND_IF` (0 = unbound), 2 s per attempt, servers tried in order. Returns `{"a":[],"aaaa":[],"ttl":n[,"error":...]}`. The only call that waits on the network (bounded by servers × 2 × timeout). Responses are parsed incrementally; records other than A/AAAA are skipped undecoded (GO-2026-5942 is in `dnsmessage.Message.Unpack`, which is not used). |

Callbacks run on one dispatcher goroutine per engine, never on wireguard-go's
goroutines or under an engine lock. Emitters never block: events (queue 256)
and log lines (queue 1024) are dropped and counted when a queue is full. At
synchronous destroy, queued events and at most 16 queued log lines are still delivered.
An in-callback destroy immediately stops delivery and discards queued callbacks;
the callback requesting destruction is the last one.
Log lines pass a redactor that masks 64-hex-digit and 44-character base64 runs.

wireguard-go itself still reads `IpcSetOperation` input with `bufio.Scanner`
and `Text()`, so UAPI lines become strings inside the pinned dependency; WGEX
code never builds one.

### Health events

wireguard-go has no hooks for handshakes or traffic, so each engine samples
`IpcGetOperation` once per second (`tx_bytes`, `rx_bytes`,
`last_handshake_time_*`, `endpoint` per peer) and derives:

| Kind | Rule |
|---|---|
| `handshakeCompleted` (1) | A peer's last handshake time advanced, or a peer seen for the first time (new or replaced by `wgex_set_config`) has a handshake newer than the previous sample. |
| `txWithoutRx` (2) | `tx_bytes` grew (data, keepalive or handshake initiation) and `rx_bytes` has not grown for 15 s (`KeepaliveTimeout + RekeyTimeout`) since the first such sample; repeated every further 15 s while it persists, with `window` 1, 2, ... and the same `since`. |
| `rx` (3) | Any peer's `rx_bytes` grew; at most one event per 5 s. |
| `endpointChanged` (4) | A peer's endpoint changed to a new value (roaming or update). |
| `engine` (0) | `socketsBumped`, `transportChanged`, `configRestored`, `deviceClosed`. |

Times are therefore accurate to the 1 s sampling period.

## Pipeline

Run under `zsh -lc` (the `just` recipes do) so `CLEAN_DEV_BUILDS` routing
applies.

```sh
Engine/scripts/build-xcframework.sh [--clean] [macos|ios|tvos]
Engine/scripts/build-test-support.sh [--clean]
Engine/scripts/verify-slices.sh [--test-support] [dir...]
Engine/scripts/smoke-macos.sh
```

`build-xcframework.sh`:

1. Asserts that `go version` and the Xcode version are at least the minimums in `Toolchain.lock` (newer is
   fine; the Xcode build string is not floor-checked, only keyed), that `go version` is at least `Engine/go/go.mod`'s
   `toolchain` line, and that the `macosx`, `iphoneos`, `appletvos`, `iphonesimulator` and
   `appletvsimulator` SDKs exist. Reuse of an existing archive needs the source digest and the toolchain
   that compiles to match: the found `go version` output and the Xcode version and build are part of the
   cache key (`toolchain_sha256` in provenance), the `Toolchain.lock` minimums are not. A floor edit never
   rebuilds; a toolchain change rebuilds once, and a reused archive's log line names the tools recorded in
   its provenance.
2. Exports `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=1
   GOARCH=arm64` and checks with `go env` that they are in effect. A caller's
   own `GOFLAGS`, `GOPROXY` or `GOTOOLCHAIN` is overridden. An import that is
   not vendored fails the build (`import lookup disabled by -mod=vendor`).
3. Builds each slice with `go build -buildmode=c-archive -trimpath
   -buildvcs=false -ldflags "-w -X main.appVersion=… -X main.build=…
   -X main.scriptSHA=…"`, a per-slice `GOCACHE` at
   `$(dependency_cache)/go-<slice>`, `CC=$(xcrun -f clang)`, and
   `CGO_CFLAGS`/`CGO_LDFLAGS` of `-isysroot <sdk> -target <triple>`.
   Intermediate archives go to `$(build_root)/engine/out/<slice>`
   (override with `WGEX_ENGINE_OUT`).
4. Runs `verify-slices.sh` on the archives, assembles the XCFramework, sorts
   its `Info.plist` library list, and verifies the packaged slices again.
5. Writes `Packages/WGEXEngine/Binary/provenance.json`: Go and Xcode
   versions, engine module version and commit, pipeline and source digests, `toolchain_sha256`, source revision,
   each slice's target, SDK and `libwgex.a` sha256, and the build time.

`app_version` and `build` come from `WGEX_APP_VERSION` / `WGEX_BUILD`, else
`MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in `Config/Base.xcconfig`,
else `0.0.0` / `0`. The engine build-info field `script_sha` carries the
source digest (`source_sha256` in provenance): engine sources, engine scripts,
`vendor/modules.txt` and the resolved app version/build. The compiling toolchain is keyed
separately (`toolchain_sha256`: the found `go version` output and the Xcode version and build), for
the production and the test-support archive alike; the `Toolchain.lock` minimums are in neither key.
The separate provenance field `script_sha256` remains the pipeline checksum of
`build-xcframework.sh`, `lib.sh` and `verify-slices.sh` concatenated in that order.
Build and test entry points reject stale or incomplete archives; run `just engine`
and `just engine-test` after changing digest inputs. An unborn checkout records
`source_revision` as `unknown`; content verification still applies.

The canonical `build_root()` resolver uses `<base>/<checkout-name>`, with base
`WGEX_BUILD_ROOT`, then `CLEAN_DEV_BUILDS`, then `${TMPDIR:-/tmp}/wgex-build`.
`--clean` rebuilds using a fresh cache under this tree's build root and preserves
shared dependency caches used by other worktrees.

### Slices

| Slice | `GOOS` | SDK | Clang target | Extra linker flags | `LC_BUILD_VERSION` platform |
|---|---|---|---|---|---|
| `macos` | `darwin` | `macosx` | `arm64-apple-macos26.0` | `-macos=26.0 -macsdk=27.0` | 1 |
| `ios` | `ios` | `iphoneos` | `arm64-apple-ios27.0` | | 2 |
| `tvos` | `ios` | `appletvos` | `arm64-apple-tvos27.0` | | 3 |

| `ios-simulator` | `ios` | `iphonesimulator` | `arm64-apple-ios27.0-simulator` | | 7 |
| `tvos-simulator` | `ios` | `appletvsimulator` | `arm64-apple-tvos27.0-simulator` | | 8 |

Go has no `GOOS=tvos`; the tvOS slices are `GOOS=ios` built against the
tvOS SDKs with a tvOS target, and the Go linker copies the platform of the
cgo objects into `go.o`. On macOS the Go linker stamps `go.o` with
minimum OS 13.0 unless `-macos`/`-macsdk` are passed; `verify-slices.sh`
catches that.

The simulator slices follow the ADR-006 amendment: with Go 1.27.3 and Xcode
27.1 every member, `go.o` included, carries platform 7 or 8 and Xcode's `ld`
links them, so golang/go#57442 does not apply to this toolchain. The provider
still cannot run in the simulator; simulator unit tests can use the real
engine in-process. `CGO_CFLAGS` carries `-O2` in front of the
`-isysroot`/`-target` flags, because setting the variable replaces Go's
default `-O2 -g`.

### Verification

`verify-slices.sh` extracts every archive member, including `go.o`, and
requires `LC_BUILD_VERSION` with the slice's platform (1, 2, 3, 7, 8) and minimum OS 26.0 for macOS and 27.0 for the other four slices (a
legacy `LC_VERSION_MIN_*` command also fails). For production archives it
also requires `_wgex_build_info` and `_wgex_free` to be exported, and fails on
any `_wgex_test_` symbol or any `gvisor.dev` content. `go version -m` cannot
read c-archives (Go 1.27.3 exits 1 with no output), so the script scans the
archive bytes for `gvisor.dev`. Linked gvisor code leaves that string in
symbol names, file paths and the embedded module information. To stop that
scan passing on an archive with no module information at all, the script
first checks that the wireguard module information is present in `go.o`.

### Reproducibility

The same sources and toolchain give byte-identical archives and XCFrameworks.
This holds for clean caches, any caller umask and any checkout path.
Three settings make that so: `ZERO_AR_DATE=1`, because Apple's `ar` otherwise
stamps the symbol-table member with the build time and the caller's uid/gid;
`umask 022` during the build, because member modes otherwise follow the
caller's umask; and the `Info.plist` sort, because `xcodebuild
-create-xcframework` orders libraries differently on every run.
`-buildvcs=false` keeps checkout metadata out of the binary; the source
revision is in `provenance.json` instead. Only `provenance.json`'s `built_at`
differs between builds. Editing any source-digest input changes
`script_sha` and therefore the archives.

### Test support

`build-test-support.sh` builds the macOS slice with `-tags wgextest` into
`Packages/WGEXEngine/Binary/WGEXEngineTest.xcframework` (module
`CWGEXEngineTest`: `wgex.h` plus `wgex_test.h`). It contains the full engine
plus the `wgex_test_*` exports, so a test target links it *instead of*
`WGEXEngine.xcframework`. Two Go c-archives cannot be linked into one binary.
It is never linked into a product, and it stays macOS-only (the Swift
loopback tests run on the host).

Test exports (`wgex_test.h`):

- `wgex_test_pair_create(json, a, b)`: two engines over loopback UDP with
  gVisor netstack tuns, throwaway keys, kernel-chosen loopback ports, each
  side serving HTTP on port 80 of its in-tunnel address (default 10.99.0.1
  and 10.99.0.2). `a`/`b` are optional `wgex_create_params` supplying
  callbacks, bind indexes and transport. `wgex_test_pair_engine` returns the
  engine handles, which work with every `wgex_*` call;
  `wgex_test_pair_info` returns handles, keys, ports and the applied UAPI
  documents; `wgex_test_pair_http_get` performs an in-tunnel GET;
  `wgex_test_pair_destroy` tears the pair down.
- `wgex_test_packetfd_echo(fd, mtu)` / `wgex_test_packetfd_echo_stop`: echo
  every datagram on a socketpair end through the tun_kind 1 device.

The test archive also needs `Security.framework` (`net/http` brings in
`crypto/x509`); the production archives do not.

## Testing

All tests are unprivileged: no utun, routes, pf or sudo; loopback sockets,
socketpairs, in-memory fake tuns and gVisor netstack tuns only.

```sh
cd Engine/go
export GOFLAGS=-mod=vendor GOPROXY=off
go test -race ./...                         # engine, cabi, transport, tun, resolver, bridge
go test -race -tags wgextest ./...          # plus test support (netstack pairs, echo)
go test -race -tags wgexcabitest ./cabi     # C-path harness: C structs, C callbacks, in-callback destroy
go test -fuzz=FuzzPublicStatsNoSecrets -fuzztime=30s ./engine
go test -fuzz=FuzzParseResponse -fuzztime=30s ./resolver
go vet ./... && staticcheck ./... && govulncheck ./...   # also with -tags wgextest / wgexcabitest
```

| Area | Tests |
|---|---|
| RT-10 | `cabi`: 8 goroutines, 1000 create/set_config/up/stats/bump/destroy cycles (Go callbacks); `-tags wgexcabitest`: 400 cycles through `wgex_create_params` and C callbacks with packet-descriptor tuns. Goroutine and descriptor counts return to the baseline. |
| RT-11 | `engine`: a failing first `set_config` closes the device; operations return `WGEX_ESTATE`; no goroutine leaks after destroy. |
| RT-12 | `engine`: a bump stuck in its retry wait (bad interface index) is cancelled by destroy well inside 100 ms. |
| RT-07 | `engine`: statistics of a live engine with private and preshared keys contain neither; `FuzzPublicStatsNoSecrets` fuzzes the `IpcGet` parser. |
| RT-03 (Go) | `engine`: three rejected documents (bad allowed IP, port in use, keepalive out of range) restore the previous configuration and the pair keeps passing traffic. |
| Sessions | Netstack loopback pairs: `update_endpoints` with an unchanged endpoint causes no handshake; `force_handshake` yields a new handshake, keeps the peer and its roamed endpoint; udp→udp `set_transport` keeps the port and the session; `bump_sockets` to `lo0` keeps traffic flowing. |
| Health | Tracker unit tests; live pairs emit `handshakeCompleted` and `rx`; a vanished peer yields `txWithoutRx` windows 1 and 2. |
| Callbacks | Destroy drains in-flight callbacks; destroy from inside a Go or C callback does not deadlock. |
| P1-19 | Packet-descriptor echo through a socketpair; two engines over packet descriptors carry IP packets; tun_kind 0 with non-zero MTU returns `WGEX_EINVAL`. |
| Resolver | Loopback DNS stub: A/AAAA, TCP fallback on truncation, NXDOMAIN/NODATA/SERVFAIL, silent-server fallback, `lo0`-bound and bad-index sockets, malformed responses (fuzzed). |
| ABI | Header versus `//export` names for both headers; `nm` of every packaged slice in the evidence. |

## Linking

The macOS slice depends on `libSystem` only. The iOS and tvOS slices (device
and simulator) also need `CoreFoundation`, which the Go runtime uses to find
the app bundle.

## Package integration

`Packages/WGEXEngine/Package.swift` enables the binary with:

```swift
.binaryTarget(name: "WGEXEngineBinary", path: "Binary/WGEXEngine.xcframework"),
```

and, in the `WGEXEngine` target:

```swift
dependencies: [
    // existing dependencies …
    "WGEXEngineBinary",
],
linkerSettings: [
    .linkedFramework("CoreFoundation", .when(platforms: [.iOS, .tvOS])),
],
```

The XCFramework carries device and simulator slices, so targets link
`WGEXEngine` on every destination; the former `WGEXEngineStub` product was removed (tests use `FakeEngine`).
