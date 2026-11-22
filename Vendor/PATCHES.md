# Vendor ledger (provenance and patches)

Every third-party source file under `Vendor/` is listed here with its origin,
pinned commit, licence, intended destination and local modifications. Each
origin directory carries its own `NOTICE` and licence text. `Tools/lint/notices.py`
generates `THIRD_PARTY_NOTICES.md` from this file; `python3 -I Tools/lint/notices.py --check`
verifies that every listed file exists and that every row with `Modifications`
`none yet` still matches its recorded SHA-256.

Rules: files are copied verbatim with their headers intact; a changed file gets
a prominent change marker in its own header, a new row in the history below, and
the new SHA-256 here. Copyleft code is never vendored (ADR-001). Commits are the
full 40-character pins in the origin sections.

## Origins

| Directory | Repository | Full commit | Licence | Scope |
|---|---|---|---|---|
| `Vendor/wireguard-apple/` | https://github.com/WireGuard/wireguard-apple | `2fec12a6e1f6e3460b6ee483aa00ad29cddadab1` | MIT (WireGuard LLC) | value types, wg-quick and UAPI codecs only |
| `Vendor/wombat-vpn/` | https://github.com/ventz/wombat-vpn | `a27bce1b6f25cccaee0fb2b4ec4107f9a101f004` | MIT (Ventz Petkov) | parser, statistics, key type, tests, QR import, on-demand rules |
| `Vendor/firezone/` | https://github.com/firezone/firezone (`swift/apple/` only) | `229ac31b37b5fbde2961e7f87df8181abd7fd46f` | Apache-2.0 (Firezone, Inc.) | NetworkExtension manager seam and its tests |

## Files

| File | Origin repo | Origin path (upstream repository-relative) | Commit | Licence | Destination package | Status | Modifications | SHA-256 (as vendored) |
|---|---|---|---|---|---|---|---|---|
| `wireguard-apple/Sources/WireGuardKit/Endpoint.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/Endpoint.swift` | `2fec12a6e1f6` | MIT | WGEXCore (reference for ADR-007 parser, P2-03) | vendored | none yet | `be390401630e0c7a16c854860d049a7653b1c699f325bc2dff55e53f041b2b63` |
| `wireguard-apple/Sources/WireGuardKit/IPAddressRange.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/IPAddressRange.swift` | `2fec12a6e1f6` | MIT | WGEXCore (P2-02, P2-03) | vendored | none yet | `aa4e91cf6a0835876cf219b2dff94dca8fceeb2c564dcd8090caa82c7d99c0c8` |
| `wireguard-apple/Sources/WireGuardKit/DNSServer.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/DNSServer.swift` | `2fec12a6e1f6` | MIT | WGEXCore (P2-02, P2-03) | vendored | none yet | `2888ce2b67d5e75d9d6e6d24c24ea87a138c8fcb2c8de2551c04c95dafb84b68` |
| `wireguard-apple/Sources/WireGuardKit/IPAddress+AddrInfo.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/IPAddress+AddrInfo.swift` | `2fec12a6e1f6` | MIT | WGEXCore (P2-02) | vendored | none yet | `7b653341e42bba28d5be0ce8c75217624d239c1c57c59c20d09a128792fa2fa2` |
| `wireguard-apple/Sources/WireGuardKit/TunnelConfiguration.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/TunnelConfiguration.swift` | `2fec12a6e1f6` | MIT | WGEXCore (reference for TunnelProfile, P2-02) | vendored | none yet | `addabfa70af57430428157729c47b0f967dcae7ebfc7f3b655461d993141c1e4` |
| `wireguard-apple/Sources/WireGuardKit/InterfaceConfiguration.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/InterfaceConfiguration.swift` | `2fec12a6e1f6` | MIT | WGEXCore (reference for TunnelProfile, P2-02) | vendored | none yet | `a8d729360b9e34ca773dd949f7686e073818efe68960ac61d0a1e2a28e4ed11b` |
| `wireguard-apple/Sources/WireGuardKit/PeerConfiguration.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/PeerConfiguration.swift` | `2fec12a6e1f6` | MIT | WGEXCore (reference for TunnelProfile, P2-02) | vendored | none yet | `27c8b53b6c216adde1cd90663799ca1bdc5380630a3c95a0c62ee1cc351111b0` |
| `wireguard-apple/Sources/WireGuardKit/PrivateKey.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardKit/PrivateKey.swift` | `2fec12a6e1f6` | MIT | reference only; ADR-005 uses CryptoKit, C x25519 code is not vendored | vendored | none yet | `64c5b742964949a4f78c3c0a86735badf62d18bd3d7da213888bf4c2884e7b4a` |
| `wireguard-apple/Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift` | `2fec12a6e1f6` | MIT | WGEXCore (reference for parseWgQuick, P2-03) | vendored | none yet | `4868b4f3a4a6adcf3f644f54330a992612e62d14bfc814f3bb5d9229be8e97ff` |
| `wireguard-apple/Sources/Shared/Model/String+ArrayConversion.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/Shared/Model/String+ArrayConversion.swift` | `2fec12a6e1f6` | MIT | WGEXCore (P2-03) | vendored | none yet | `c9c30bf1524bed1360efc1cab375fd040a41621a2ba4e161114dd71baae89770` |
| `wireguard-apple/Sources/WireGuardApp/Tunnel/TunnelConfiguration+UapiConfig.swift` | https://github.com/WireGuard/wireguard-apple | `Sources/WireGuardApp/Tunnel/TunnelConfiguration+UapiConfig.swift` | `2fec12a6e1f6` | MIT | WGEXCore (reference for UAPI codec, P2-05) | vendored | none yet | `cade59936971e7cd6155c09298676033135980d74fbf18c89b4bc1535e68a231` |
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/WgQuick.swift` | https://github.com/ventz/wombat-vpn | `Packages/TunnelCore/Sources/TunnelCore/WgQuick.swift` | `a27bce1b6f25` | MIT | WGEXCore (adapted into parseWgQuick, P2-03) | vendored | none yet | `e4e5e99f832b2f6c25a8b1100c8d6720e9cc76fdf66d799fc36976d720b8f45d` |
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/RuntimeStats.swift` | https://github.com/ventz/wombat-vpn | `Packages/TunnelCore/Sources/TunnelCore/RuntimeStats.swift` | `a27bce1b6f25` | MIT | WGEXCore (adapted into UAPIStatsDecoder, P2-05, P2-15) | vendored | none yet | `d3e7e23dfd65056f00a58d02b8449d236d01799e7e3c5e01a85ce7af1850a242` |
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/WireGuardKey.swift` | https://github.com/ventz/wombat-vpn | `Packages/TunnelCore/Sources/TunnelCore/WireGuardKey.swift` | `a27bce1b6f25` | MIT | WGEXCore (key handling, P2-06) | vendored | none yet | `ffe35cfc411c36b14ab3876109552f40f551a60be29079691daf9d2ade40a53c` |
| `wombat-vpn/Packages/TunnelCore/Tests/TunnelCoreTests/WgQuickTests.swift` | https://github.com/ventz/wombat-vpn | `Packages/TunnelCore/Tests/TunnelCoreTests/WgQuickTests.swift` | `a27bce1b6f25` | MIT | WGEXCore tests (adapted vectors, P2-03) | vendored | none yet | `b8134eb2ef136ec8b40771fda9d4a2a46bc64d9430b5d7a48ae82c7a75579496` |
| `wombat-vpn/Packages/TunnelCore/Tests/TunnelCoreTests/ReviewAndStatsTests.swift` | https://github.com/ventz/wombat-vpn | `Packages/TunnelCore/Tests/TunnelCoreTests/ReviewAndStatsTests.swift` | `a27bce1b6f25` | MIT | WGEXCore tests (adapted vectors, P2-03, P2-15) | vendored | none yet | `ffa541e62cb19172a91a863a86c2a88a08b0ef2540c03a8f3140002248e6883c` |
| `wombat-vpn/App/Model/QRImport.swift` | https://github.com/ventz/wombat-vpn | `App/Model/QRImport.swift` | `a27bce1b6f25` | MIT | WGEXProfileStore (bounded Vision QR decoding, P2-10) | vendored | none yet | `da0238cab8a32445a6ae6c1033211cd735477584272994427df5b05a6e03168c` |
| `wombat-vpn/App/Model/NERules.swift` | https://github.com/ventz/wombat-vpn | `App/Model/NERules.swift` | `a27bce1b6f25` | MIT | WGEXPolicy (on-demand compiler reference, P2-11) | vendored | none yet | `0221ff3142282a6f5cd43432201c688b7bda727fdeece606d1ba7d69cda73b16` |
| `firezone/FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift` | https://github.com/firezone/firezone | `swift/apple/FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift` | `229ac31b37b5` | Apache-2.0 | WGEXBackendNE / WGEXNEClient (NEManagerClient seam, P1) | vendored | none yet | `ca0f827dfdc60d9257983b4eb9f76b802427f7ccb4d2c025d677512965c0bc60` |
| `firezone/FirezoneKit/Tests/FirezoneKitTests/VPNConfigurationManagerTests.swift` | https://github.com/firezone/firezone | `swift/apple/FirezoneKit/Tests/FirezoneKitTests/VPNConfigurationManagerTests.swift` | `229ac31b37b5` | Apache-2.0 | WGEXBackendNE tests (P1) | vendored | none yet | `3c4259735882cd701ae1fc84a4656e127e000cb7d486fa2466ed5bf319aa6960` |
| `wireguard-apple/COPYING` | https://github.com/WireGuard/wireguard-apple | `COPYING` | `2fec12a6e1f6` | MIT | licence text, ships with every redistribution | vendored | none yet | `7c8284cbf3bead1d4f9065dfd3474755364b061c4b7d1c21fb490f9c4bd1d955` |
| `wombat-vpn/LICENSE` | https://github.com/ventz/wombat-vpn | `LICENSE` | `a27bce1b6f25` | MIT | licence text, ships with every redistribution | vendored | none yet | `ed7078c356edb5175f794ea3f2264a4a656e16527544be769f21463bf44366bd` |
| `firezone/LICENSE` | https://github.com/firezone/firezone | `swift/apple/LICENSE` | `229ac31b37b5` | Apache-2.0 | licence text, ships with every redistribution | vendored | none yet | `81651d7d700a9c13ea22d5a417d49b03699f364a5bf0c0d574e08ac0ce258358` |

Every file listed in the P0-06 scope is recorded above by its upstream
repository-relative path at the pinned commit; no files remain to be fetched.

## Go modules

Go dependencies live in `Engine/go/vendor/` (P0-05) and are covered by
`go-licenses report` in `Tools/lint/notices.py`, not by this table. The
`golang.zx2c4.com/wireguard` pin (ADR-005) is recorded in `Engine/go/go.mod`;
pin bumps add a line to the history below after the pin-bump checklist.

The Go modules below are reached only through test builds, or only on
Windows, and are not in the go-licenses report of the shipped engine.
`THIRD_PARTY_NOTICES.md` reproduces each licence text in full; the version and
licence here must agree with it.

| Go module | Version | Licence | Reach |
|---|---|---|---|
| `github.com/google/btree` | `v1.1.2` | Apache-2.0 | `-tags wgextest` only |
| `golang.org/x/time` | `v0.7.0` | BSD-3-Clause | `-tags wgextest` only |
| `gvisor.dev/gvisor` | `v0.0.0-20250503011706-39ed1f5ac29c` | Apache-2.0 (the licence file also carries an MIT grant, reproduced with it) | `-tags wgextest` only |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | MIT | Windows builds only, never built by WGEX |

## Explicitly excluded (never vendor)

| Path or project | Reason |
|---|---|
| Wombat `Vendor/WireGuardKit` | carries the RNG-in-assert C code; optional engine and vendor files carry copyleft or OpenSSL terms |
| Firezone `elixir/` and anything outside `swift/apple/` | source-available Elastic-2.0 grant on elixir/; root Apache does not extend to it; server, telemetry and Rust engine out of scope |
| wireguard-apple MiniZip, C key code, Go bridge | separate provenance, RNG hazard, ADR-005 (bridge is WGEX-owned) |
| Passepartout, Partout, sing-box, UpVPN app, wg-quick, IVPN, NetBird, Mullvad | copyleft licences (ADR-001); reference only, reimplement |

## History

| Date | Change |
|---|---|
| 2026-10-25 | Initial vendoring (P0-06): 20 source files and 3 licence texts, no modifications. |

## Adaptations

All paths below are relative to this repository. Vendored files remain unchanged;
original Files-table hashes and notices remain authoritative.

| Vendored file | Commit | WGEX destination file | Changes |
|---|---|---|---|
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/WgQuick.swift` | `a27bce1b6f25` | `Packages/WGEXCore/Sources/WGEXCore/Configuration/WgQuickParser.swift` | Section/key parsing, comments, BOM, CRLF, DNS search domains and diagnostics adapted to bounded UTF-8 byte views; direct secret-buffer decoding; strict duplicate, hook and AmneziaWG rejection; canonical caps and validation. UTF-8 scanning is new WGEX code in `ConfigurationUTF8.swift`. |
| `wireguard-apple/Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift` | `2fec12a6e1f6` | `Packages/WGEXCore/Sources/WGEXCore/Configuration/WgQuickParser.swift` | Section vocabulary, attribute collation and duplicate-peer checks adapted to throwing value constructors and named diagnostics; no string storage of secret fields. |
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/WgQuick.swift` | `a27bce1b6f25` | `Packages/WGEXCore/Sources/WGEXCore/Configuration/WgQuickSerialiser.swift` | Normalised field ordering and list formatting; public placeholders and secret-byte restoration replace string key interpolation; lossless original export verifies the retained original hash. |
| `wireguard-apple/Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift` | `2fec12a6e1f6` | `Packages/WGEXCore/Sources/WGEXCore/Configuration/WgQuickSerialiser.swift` | Standard wg-quick field spelling and normalised section output adapted to public profiles and separately owned secrets. |
| `wireguard-apple/Sources/WireGuardApp/Tunnel/TunnelConfiguration+UapiConfig.swift` | `2fec12a6e1f6` | `Packages/WGEXCore/Sources/WGEXCore/UAPI/UAPIEncoder.swift` | UAPI attribute vocabulary and hex key representation adapted from the reference decoder into full-replace and endpoint-only encoders; private fields write directly into wiped buffers; literal endpoints required. |
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/RuntimeStats.swift` | `a27bce1b6f25` | `Packages/WGEXCore/Sources/WGEXCore/UAPI/UAPIStatsDecoder.swift` | Public counter, endpoint, handshake and keepalive mapping adapted to bounded engine JSON; rejects secret member names before decoding, including nested/escaped/overwritten members; accepts bridge RFC 3339 and plan Unix timestamps. |
| `wombat-vpn/Packages/TunnelCore/Sources/TunnelCore/RuntimeStats.swift` | `a27bce1b6f25` | `Packages/WGEXCore/Sources/WGEXCore/Status/RateSampler.swift` (removed in 9f18703) | Latest-handshake and counter aggregation adapted into monotonic per-peer deltas, independent counter resets, generation isolation and bounded 30-second history; wall clock supplied explicitly. |
| `wombat-vpn/Packages/TunnelCore/Tests/TunnelCoreTests/WgQuickTests.swift` | `a27bce1b6f25` | `Packages/WGEXCore/Tests/WGEXCoreTests/WgQuickParserTests.swift`, `WgQuickSerialiserTests.swift` | Parser/round-trip/hidden-secret/line-number/control/endpoint/CIDR/MTU/keepalive cases ported to WGEX Swift Testing and repository fixture keys. Repeated list keys, hooks and low IPv6 MTU now reject under ADR-007. Key/value-type tests already covered by the first core run are not duplicated. |
| `wombat-vpn/Packages/TunnelCore/Tests/TunnelCoreTests/ReviewAndStatsTests.swift` | `a27bce1b6f25` | `Packages/WGEXCore/Tests/WGEXCoreTests/WgQuickParserTests.swift`, `UAPICodecTests.swift`, `RateSamplerTests.swift` (removed in 9f18703) | BOM, duplicate-peer, bidi/C1 controls, DNS cap, stats counters/zero-handshake/keepalive and handshake-age vectors adapted to WGEX diagnostics and JSON; raw UAPI secret skipping becomes JSON secret rejection. Review/UI/name/control-protocol tests outside these tickets are not ported. |
| `firezone/FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift` | `229ac31b37b5fbde2961e7f87df8181abd7fd46f` | `Packages/WGEXBackendNE/Sources/WGEXNEClient/VPNManagerSystem.swift` | Protocol/factory seam adapted to Sendable immutable manager records; NE objects confined to the real MainActor adapter. |
| `firezone/FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift` | `229ac31b37b5fbde2961e7f87df8181abd7fd46f` | `Packages/WGEXBackendNE/Sources/WGEXNEClient/NEManagerClient.swift` | Provider-identity filtering, load/save/reload and equivalent-write skipping adapted to a FIFO actor gate, one reload/retry and a failed-write latch; no MDM identity repair. |
| `firezone/FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift` | `229ac31b37b5fbde2961e7f87df8181abd7fd46f` | `Packages/WGEXBackendNE/Sources/WGEXNEClient/NetworkExtensionManagerSystem.swift` | Real preference/session operations isolated behind VPNManagerSystem; explicit protocol flags and ordered on-demand rule mapping; discarded manager objects on reload. |
| `firezone/FirezoneKit/Tests/FirezoneKitTests/VPNConfigurationManagerTests.swift` | `229ac31b37b5fbde2961e7f87df8181abd7fd46f` | `Packages/WGEXBackendNE/Tests/WGEXNEClientTests/ManagerTests.swift` | Foreign-provider fake/factory pattern adapted to an in-memory actor; faulted saves, latch, serialisation, supersession, ordered status, manual-stop on-demand and backend mapping tests. |
