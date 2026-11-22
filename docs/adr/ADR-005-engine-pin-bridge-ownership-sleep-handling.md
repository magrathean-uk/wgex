# ADR-005 Engine pin, bridge ownership, sleep handling

Status: Accepted 2026-10-25

**Decision.**
- `golang.zx2c4.com/wireguard` pinned at `b3bc704ef0ee21a36298601a9e1e5ff90377ac52`; dependencies vendored and committed; monthly upstream review with a **pin-bump checklist** (read the diff, `govulncheck`, full bridge regression set, note in `Vendor/PATCHES.md`).
- WGEX-owned Go module with the bridge as `package main` (`-buildmode=c-archive` requires it) and domain logic in package `engine`; the ABI in `architecture.md` §6.2. Nothing from upstream `api-apple.go` (WireGuardKitGo) is copied.
- **Stock Go runtime, no runtime patch.** Keypair age inside wireguard-go uses Go's monotonic clock, which excludes sleep on Darwin; the server counts real time and rejects keypairs older than 180 s. Therefore `sleep()` never tears the engine down, and on wake the owner calls `wgex_force_handshake` (per peer `ExpireCurrentKeypairs` + `SendHandshakeInitiation`, no peer replacement, roamed endpoints preserved) whenever the wall-clock handshake age exceeds 110 s or the measured sleep exceeds 5 s. RT-18 covers pre-aged keypairs and the responder role. If device tests still show timer problems, a follow-up ADR rebases the `mach_continuous_time` patch onto Go 1.27 with a hard build failure when a hunk does not apply.
- Endpoint changes use `wgex_update_endpoints` (partial UAPI, `update_only=true`), never a full replace; on iOS/tvOS the engine applies `DisableSomeRoamingForBrokenMobileSemantics` after each apply (`mobile_quirks`).
- Key generation and derivation use CryptoKit `Curve25519.KeyAgreement`; the C x25519 code is not vendored.

