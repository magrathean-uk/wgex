# 04. Security and threat model

## 1. Assets

| Asset | Where it lives | Impact if lost |
|---|---|---|
| WireGuard private keys, preshared keys, carrier UUIDs, WS paths | Keychain (apps); daemon root store while intended-up or start-before-login | Impersonation of the user's peer; relay abuse |
| Traffic confidentiality and routing integrity | Kernel routes, pf anchor, NE settings | Clear-text leak; DNS leak; MITM via wrong path |
| Root privilege on the Mac | Daemon, bundle | Full machine compromise |
| Device networking integrity | NE settings, pf | Device without connectivity |
| Truth of the status display | UI, Live Activity, notifications | User believes they are protected when not |

## 2. Trust boundaries and adversaries

1. **Hostile configuration input** (QR, `.conf`, ZIP, pairing payload, pasted text, Open-In): bounded parse, never interpreted as commands.
2. **Other processes of the same user on the Mac**: can talk to the daemon's Mach service only if they pass the code-signing requirement; **until secure install has completed, such a process can modify the user-owned bundle and obtain root** (ADR-025); App Management TCC is the only interim control. After secure install the bundle is root-owned and the daemon refuses privileged operations while any bundle file is non-root-writable.
3. **Other local users**: cannot read a user's Keychain items; cannot drive another user's profiles; cannot change global protection settings without the admin right; cannot start a tunnel unless they are the console user (authorisation table in `architecture.md` §5).
4. **Network adversary**: drop, inject, redirect; mitigated by WireGuard, bound sockets, REALITY/TLS authentication of carriers with named-certificate validation even for numeric addresses, and the kill switch during reconnects.
5. **Malicious app on iOS/tvOS**: sandbox; the provider trusts only its containing app.
6. **Supply chain**: pinned commits, vendored Go deps, offline builds (`GOTOOLCHAIN=local`, `-mod=vendor`, `GOPROXY=off`), committed `Package.resolved` verified against `Toolchain.lock`, SBOM, licence scan, Sparkle key handling and rotation runbook.
7. **Apple platform changes**: pf outside API; NE API churn; mitigated by the per-release matrix, the liveness monitor and the designed sysext fallback.
8. **The owner's own session**: agents and tests must never break the host Mac's connectivity (ADR-017, hard rules 1, 11 and 12).

## 3. Controls by component

### 3.1 Mac daemon
- Launched by launchd from `BundleProgram`; refuses to run outside `/Applications` in Release; performs secure install after approval (root ownership, non-writable); launch constraints if enforced; refuses privileged operations while the bundle is writable by non-root.
- XPC: listener-level and per-connection code-signing requirements with Developer ID OIDs and `get-task-allow` exclusion; `.privileged` lookups on the client; secrets only after a successful `hello`; authorisation by uid, console session and the `manage-protection` admin right; no cross-uid access; anti-rollback floor and `minClientBuild`.
- Closed message schema (binary plist Codable enums); limits; daemon-allocated generations; no file paths, routes or resolvers from the client outside the validated profile.
- No shell. External processes: `/sbin/pfctl` (mutating, fixed argv) and `/usr/sbin/scutil --dns` (read-only, for verification and diagnostics). Routes, addresses and the DNS key are native calls.
- State directory 0700 root; files 0600; dirfd-relative opens with `O_NOFOLLOW`; ownership and mode verified; secrets wrapped with a key in the System keychain or Secure Enclave; Time Machine exclusion applied and tested; `RLIMIT_CORE = 0`.
- pf: all-`quick` anchor, no `set` lines, DNS block before LAN, LAN scoped to the underlay's subnet, tunnel ranges blocked on the underlay, DHCP in and out, NDP without redirects, PMTU messages from endpoints only, journalled enable token, per-interface state kills, evaluation canary and liveness monitor in every enforcing state, stock-anchor check.
- Resolution under blocking: root-only `UnderlayResolver` sockets bound to the underlay with a matching pf pass; mDNSResponder never relied upon while blocking.
- Crash safety: journal with reconciliation that downgrades a persisted `connected` policy before anything else; pf rules and token persist in the kernel; intended-up secrets persist in the root store so recovery needs no app.
- Updates: version handshake, `prepareForUpdate` needs the admin right and a newer client, atomic bundle replacement, authorised installer for the root-owned bundle.
- CLI never reads the Keychain; no symlink creation under `/usr/local`.

### 3.2 NE provider
- Only the containing app can message the provider; messages validated and bounded.
- Secrets fetched by persistent reference at start; never written by the provider.
- Settings verified before `active`; `allowFailover = false`; `excludedRoutes` only for the documented tvOS Allow LAN case.
- Memory governor; `MemoryExceptionDiagnostic` on iOS 27.
- Descriptor scan in Go with the packet-descriptor bridge as fallback.

### 3.3 Apps
- Keychain with `ThisDeviceOnly`, no sync; Mac app carries the restricted entitlements with embedded profiles.
- Import pipeline: size and type guards, bounded ZIP reader, parser diagnostics, review screen, no auto-follow of QR URLs, no execution; Open-In routes to review.
- Pairing: QR-authenticated key or commit-then-reveal with a mutually confirmed 6-digit exporter-derived SAS before sealing; no session id in Bonjour TXT; attempts counted after the SAS stage; no system URL scheme; ≤ 64 KiB; single-use 120 s sessions.
- Mac app validates the daemon's identity before sending secrets; shows explicit states for unapproved, missing, mismatched, downgraded and insecure-install.
- No analytics, no crash SDK; network use limited to tunnel, pairing, Sparkle.
- Live Activity never shows a protection colour when stale; profile name hidden by default on the Lock Screen.
- Pasteboard copies local-only with expiry; `SecretField` reveal-once (iPhone, iPad and TV).
- Mac Edit sheet: the private and preshared key rows show fixed-length dots and reveal on click; a second click or Space hides the key again. A revealed key is read from the editor model, never copied into a field of its own; Paste replaces it only with a valid key. It hides on focus loss, when its window resigns key or is minimised, on sheet close, on app deactivation and when the key changes elsewhere, and it is never placed in an accessibility label or value while hidden. Edit as Text holds the configuration with its keys only while that view is open and drops it on return to the form, close, window resign and app deactivation; text dropped unparsed is announced.

### 3.4 Engine and transports
- wireguard-go pinned and vendored; `govulncheck` in `just lint`; pin-bump checklist.
- Carriers: utls pinned; fingerprints restricted to MLKEM-capable presets; REALITY failure surfaced once with backoff (no probing pattern); WebSocket/TLS validates the named certificate against system roots; no `insecure` option exists.
- Framing validated; oversize frames dropped and counted; write deadlines; bounded queues.

## 4. Protection semantics (what the UI may claim)

| Claim | macOS | iOS/iPadOS | tvOS |
|---|---|---|---|
| Protected | Routes, DNS key, pf connected policy verified, canary hit, engine up | NE settings applied; on-demand armed | NE settings applied; on-demand armed |
| Blocked | pf connecting/error/lockdown verified and canary hit | Only lifecycle states measured as blocking by P4-13a with `includeAllNetworks` on | never claimed |
| Unprotected | Disconnected, no lockdown; manual stop | Disconnected or manual stop | Disconnected |
| Captive window | Routes and DNS withdrawn, narrowed pass-out, countdown | not available | not available |
| Unknown | Verification failed, canary not hit, pf disabled, stock anchor missing, secure install pending | Settings pending | Settings pending |

Known gaps shown in Settings → Protection: macOS early-boot window until the daemon's first enforcing status; pf pass rules persist while the daemon is dead (captive window); logout without Lockdown leaves traffic unprotected; Apple services that bypass routing on some macOS builds; iOS `includeAllNetworks` update lockout and real-IP leak during updates; CarPlay/Personal Hotspot with local sharing on, local DNS/mDNS with it off; tvOS no kill switch; trusted Wi-Fi names can be imitated; LAN allowance; interim admin-to-root exposure before secure install.

## 5. Logging and redaction rules

Private by default; public only phase names, error codes, interface names, generations, counts, durations. Never logged: private keys, PSKs, VLESS UUIDs, REALITY keys, WS paths, raw UAPI, raw configuration text, pairing payloads, Keychain references. `.private`: endpoints, hostnames, IPs, SSIDs, SNIs, profile names. Redactor: exact-match from the store (12-character partial matches included), then patterns (base64/base64url 42–44 chars, 64-hex, UUIDs, IP literals and CIDR shorthand, `PrivateKey`/`PresharedKey` lines, `path=`/`"path":`/`sni`/`host` values); corpus of ≥ 150 seeded leaks including split lines must be fully caught.

## 6. Security tests (minimum)

- Forged client suite: unsigned, ad hoc, wrong team, right team wrong identifier, `get-task-allow` build, old protocol, old `clientBuild`, a genuinely signed old `WGEXDaemon` registered as a user LaunchAgent on the same Mach name (client must refuse it: `.privileged` lookup) → all rejected before decoding.
- Cross-user suite (VM, two users): user B cannot see, start, stop or remove A's profiles, cannot change lockdown/LAN/captive state, cannot start a tunnel while A is the console user, cannot stop the daemon, and B's logs and diagnostics contain none of A's identifiers.
- Hostile IPC fuzz; filesystem races; symlinked `/usr/local` is irrelevant (no symlink creation).
- Secret scan of logs, journal, diagnostics bundle, envelope bytes (raw, base64, hex), `ps -E`, environment during a full connect/disconnect/update cycle → zero hits.
- Parser, ZIP and VLESS-framing fuzzing → no crash, no hang > 50 ms.
- Leak harness verdicts (`05-test-strategy.md` §6) for every protection state transition, including DNS to the LAN gateway with Allow LAN on, UDP from source port 68 to an external host while blocked, tunnel-range traffic while the tunnel is down, pre-existing connections at connect time, captive window during and after, update handoff, daemon crash with the app quit.
- Pairing MITM harness; attempt exhaustion by a third device; Safari-launched `wgex-pair://` is ignored.
- `govulncheck`, licence scan, SBOM diff, public-prose denylist per release.

## 7. Residual risks (accepted, documented in README)

1. Interim admin-to-root exposure before secure install completes (ADR-025).
2. macOS early-boot leak window: accepted; Lockdown enforces once the daemon, after launch, reports its first enforcing status (ADR-009); captive pass rules persisting while the daemon is dead.
3. pf and route-table use outside Apple's supported API surface (ADR-003).
4. tvOS has no kill switch.
5. iOS `includeAllNetworks` update lockout and update-time leak (Apple bugs).
6. Daemon store secrets rely on FileVault at rest.
7. Logout without Lockdown is unprotected.
