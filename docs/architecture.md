# 02. Architecture

This document is the contract implementers build against. Names are binding. Changes to this contract go through an ADR draft, never as a silent edit by an implementer. Revision 2 (25 October 2026) incorporates the five-lens adversarial review; the superseded revision-1 designs are noted where it helps a reader of the research.

## 1. Component map

```
                       ┌──────────────────────────────────────────────────────┐
                       │  Packages (platform-agnostic unless noted)           │
                       │  WGEXCore  WGEXProfileStore  WGEXPolicy  WGEXPairing │
                       │  WGEXEngineInterface (protocols, no binary)          │
                       │  WGEXEngine (Swift over libwgex.a; daemon/providers) │
                       │  WGEXBackendMac: DaemonProtocol · DaemonClient · DaemonCore │
                       │  WGEXBackendNE:  NEClient · NEProvider               │
                       │  WGEXUI  WGEXDiagnostics  WGEXTesting  WGEXUITesting │
                       └──────────────────────────────────────────────────────┘
      macOS                          iOS / iPadOS                       tvOS
┌────────────────────┐        ┌────────────────────────┐        ┌────────────────────┐
│ WGEX.app (user)    │        │ WGEX.app               │        │ WGEX.app           │
│  SwiftUI, Sparkle  │        │  SwiftUI, Live Activity│        │  SwiftUI, focus UI │
│  MenuBarExtra      │        │  QR camera, pairing tx │        │  pairing rx, paste │
│  Helpers/wgex CLI  │        └──────────┬─────────────┘        └──────────┬─────────┘
└─────────┬──────────┘                   │ NETunnelProviderManager          │
          │ NSXPC (.privileged), mutual  │ sendProviderMessage              │
          │ code-signing requirements    ▼                                  ▼
          ▼                     ┌────────────────────────┐        ┌────────────────────┐
┌────────────────────┐          │ WGEXTunnel.appex       │        │ WGEXTunnel.appex   │
│ WGEXDaemon (root)  │          │  ProviderController    │        │  ProviderController│
│  TunnelController  │          │  EngineActor(libwgex)  │        │  EngineActor       │
│  RouteTable/DNS/pf │          │  NE settings, memory   │        │  NE settings       │
│  Journal, secrets  │          │  governor              │        │                    │
└────────────────────┘          └────────────────────────┘        └────────────────────┘
   utun + routes + pf anchor      utun descriptor from NE             utun descriptor
```

Networking ownership is always in the privileged or extension process. UI processes hold no tunnel sockets, never poll on timers while invisible, and can be killed at any time without affecting the tunnel. The Go engine (`libwgex.a`) is linked only into `WGEXDaemon`, `WGEXTunnel-iOS` and `WGEXTunnel-tvOS`; `just check` asserts with `nm` that no app or CLI binary contains `_wgex_` or `_cgo_` symbols.

## 2. Packages, products and dependency rules

| Package → product | Depends on | Platforms | Isolation default | Contents |
|---|---|---|---|---|
| `WGEXCore` | Foundation, CryptoKit, Network (value types only) | all | nonisolated | Models, validation, `.conf` codec, UAPI codec, keys, `SecretBytes`, stats DTO, policy types, error taxonomy, `TunnelBackend` protocol, `BuildIdentifiers` (generated), `FeatureFlags` |
| `WGEXProfileStore` | WGEXCore | all | nonisolated | Profile documents, Keychain and daemon secret stores behind `SecretStore`, journal, migrations, import pipeline, bounded ZIP reader |
| `WGEXAppComposition` | WGEXCore, WGEXProfileStore | all | nonisolated | Shared profile/secret commit, rollback, editor key reload, retirement and copying; iOS persistent references and tvOS SecretID identities |
| `WGEXPolicy` | WGEXCore | all | nonisolated | Health evaluator, failover engine, on-demand compiler, captive-window model; pure |
| `WGEXEngineInterface` | WGEXCore | all | nonisolated | `EngineControlling` protocol, `EngineConfiguration`, `EngineEvent`, `TunnelStatistics` decoding; no binary |
| `WGEXEngine` | WGEXCore, WGEXEngineInterface, binary target `WGEXEngineBinary` (`WGEXEngine.xcframework` in the package's `Binary` directory) | macOS, iOS, tvOS, device and simulator slices (ADR-006 amendment) | nonisolated, strict memory safety | `EngineActor: EngineControlling`, C trampolines, memory governor |
| `WGEXBackendMac` → `WGEXDaemonProtocol` | WGEXCore | macOS | nonisolated | Envelope, `Request`/`Reply`/`Event`, secrets wire layout, requirement strings, authorisation table |
| `WGEXBackendMac` → `WGEXDaemonClient` | WGEXCore, WGEXDaemonProtocol, WGEXProfileStore | macOS | nonisolated | `DaemonClient: TunnelBackend`, `ServiceController: ServiceControlling` |
| `WGEXBackendMac` → `WGEXDaemonCore` | WGEXDaemonProtocol, WGEXEngineInterface, WGEXProfileStore, WGEXPolicy, WGEXCore, SystemConfiguration, `CWGEXSysShim` | macOS | nonisolated | `TunnelController`, `UTunDevice`, `RouteTable`, `DNSConfigurator`, `PacketFilter`, `UnderlayMonitor`, `UnderlayResolver` bridge, `Journal`, `DaemonSecretStore`, `ProfileRegistry`, `PowerMonitor`, `LoginSessionMonitor`, `LabGuard`, `ProtectionVerifier` |
| `WGEXBackendNE` → `WGEXNEClient` | WGEXCore, WGEXPolicy, WGEXProfileStore, NetworkExtension | iOS, tvOS | nonisolated | `NEManagerClient: TunnelBackend`, `ProtocolConfigurationBuilder`, manager/session/factory protocols |
| `WGEXBackendNE` → `WGEXNEProvider` | WGEXCore, WGEXPolicy, WGEXProfileStore, WGEXEngineInterface, NetworkExtension | iOS, tvOS | nonisolated | `ProviderController`, `NESettingsGenerator`, `PhysicalEndpointResolver` (`ProviderEndpointResolving`), path monitor, provider message handling |
| `WGEXPairing` | WGEXCore, Network, CryptoKit | all | nonisolated | Session, QR codec, framing, HPKE, commitment, SAS, state machines, Bonjour advertiser/browser |
| `WGEXUI` | WGEXCore, WGEXPolicy, SwiftUI | all | MainActor | Tokens, components, view models; builds for macOS, iOS and tvOS in `just check` (`#if !os(tvOS)` around reorder support) |
| `WGEXActivityShared` | WGEXCore, ActivityKit | iOS | nonisolated | `TunnelActivityAttributes` shared by the app and the Live Activity extension |
| `WGEXDiagnostics` | WGEXCore | all | nonisolated | Log categories, ring buffer, redactor, bundle builder (stored-zip writer) |
| `WGEXTesting` | WGEXCore, WGEXPolicy, WGEXEngineInterface | all | nonisolated | `FakeTunnelBackend`, `FakeEngine: EngineControlling`, `FakeServiceController`, `FaultInjector`, `FakeClock`, fixtures, secret scanner |
| `WGEXUITesting` | WGEXCore, WGEXUI, WGEXTesting | all | MainActor | Preview fakes, screenshot harness helpers |

Rules: `WGEXCore` imports no Apple framework beyond Foundation, CryptoKit and Network value types. Nothing in a `Backend` package imports SwiftUI. Apps and the CLI link client products only; providers and the daemon link `WGEXEngine`. Provider-linked packages set `APPLICATION_EXTENSION_API_ONLY = YES`. Apps link `WGEXTesting` in Debug only (`#if DEBUG`, config-scoped dependency) for launch-argument fakes. Every package has a Swift Testing target. `Tools/lint/check-package-deps.sh` enforces this table.

`CWGEXSysShim` is a tiny C target (MIT, our own) exporting plain functions for the function-like ioctl macros Swift cannot import: `wgex_sioc_aifaddr`, `wgex_sioc_aifaddr_in6`, `wgex_sioc_sifmtu`. The utun descriptor scan on iOS/tvOS is done in Go (`wgex_find_utun_fd`) because `<sys/kern_control.h>` is absent from the iOS and tvOS SDKs.

## 3. Data model (`WGEXCore`)

```swift
public struct TunnelProfile: Codable, Sendable, Identifiable, Hashable {
    public let id: UUID
    public var schemaVersion: Int                 // 1
    public var name: String                       // 1...128 chars, no control chars
    public var interface: InterfaceConfiguration
    public var peers: [PeerConfiguration]         // 1...1024, unique public keys
    public var secrets: SecretReferences          // where the private key, PSKs and carrier credentials live
    public var transport: TransportPolicy         // candidates; `.udp` only until phase 6
    public var protection: ProtectionPolicy       // per-profile protection options (global Mac settings live elsewhere)
    public var onDemand: OnDemandPolicy           // iOS/tvOS
    public var macOptions: MacProfileOptions      // startBeforeLogin, autoConnectAtLogin
    public var original: OriginalText?            // retained import text with secret placeholders
    public var createdAt: Date
    public var updatedAt: Date
}

public struct InterfaceConfiguration: Codable, Sendable, Hashable {
    public var addresses: [IPAddressRange]        // ≥1
    public var listenPort: UInt16?
    public var mtu: UInt16?                       // validated 576/1280...9000; effective MTU is computed per backend (§7.2, §9)
    public var dns: [DNSServer]                   // ≤64
    public var searchDomains: [String]
    public var publicKey: PublicKey               // derived at import; display without unlocking secrets
}

public struct PeerConfiguration: Codable, Sendable, Hashable, Identifiable {
    public var id: PublicKey { publicKey }
    public var publicKey: PublicKey
    public var hasPresharedKey: Bool
    public var allowedIPs: [IPAddressRange]       // ≤4096
    public var endpoint: Endpoint?                // host or literal + port
    public var persistentKeepalive: UInt16?
}

public struct SecretReferences: Codable, Sendable, Hashable {
    public var privateKey: SecretRef              // .keychain(persistentRef) | .daemonStore(id)
    public var presharedKeys: [PublicKey: SecretRef]
    public var carrierCredentials: [TransportID: SecretRef]
}

public struct ProtectionPolicy: Codable, Sendable, Hashable {
    public var ios: IOSProtection                 // includeAllNetworks, excludeLocalNetworks, excludeCellularServices, excludeAPNs, excludeDeviceCommunication (all explicit; applied on NEVPNProtocol)
    public var tv: TVProtection                   // enforceRoutes (true), allowLAN (true; excludedRoutes for LAN prefixes)
    public var dnsPolicy: DNSPolicy               // .tunnelAll | .split([String]) | .systemDefault (warns)
    public var ipv6Policy: IPv6Policy             // .tunnel | .blockOutside | .allowOutside (required when the profile is v4-only with a full-tunnel route)
}

/// Daemon-global Mac settings, not per profile (XPC `setGlobalSettings`).
public struct MacGlobalSettings: Codable, Sendable, Hashable {
    public var lockdown: Bool                     // ADR-009
    public var allowLAN: Bool                     // default true
    public var captiveWindowSeconds: Int          // default 300
    public var notifications: Bool                // default true
}

public enum OnDemandPolicy: Codable, Sendable, Hashable {
    case off
    case always(exceptSSIDs: [String])            // interfaceTypeMatch .any; tvOS ignores the SSID list
    case wifiOnly(exceptSSIDs: [String])
    case cellularOnly                             // iOS only
}

public struct OriginalText: Codable, Sendable, Hashable {
    public var text: String                       // secrets replaced by "$WGEX_SECRET:<ref-id>$"
    public var sha256OfOriginal: Data
}

public struct FeatureFlags: Codable, Sendable, Hashable {
    public var relayTransports: Bool              // feature flag, default false (Packages/WGEXCore/Sources/WGEXCore/Values/FeatureFlags.swift:6)
}
```

Value types `IPAddressRange`, `Endpoint`, `DNSServer`, `PublicKey` follow the official MIT models with validation moved into throwing initialisers (no clamping, no `fatalError`). `PrivateKey` and `PresharedKey` wrap `SecretBytes`.

**OriginalText redaction (fix 1, 25 October 2026, from fuzz reproducer s7-i904).** Besides replacing parsed secret values with `$WGEX_SECRET:<ref-id>$`, the parser scans the retained bytes and replaces every unparsed key-shaped token (44-character padded base64, 43-character base64url, 64-hex) in comments, unknown keys and rejected lines with `$WGEX_REDACTED$`; parsed public keys stay intact. `OriginalText.wasRedacted` marks the altered case, and lossless export is byte-identical only when it is false.

### `SecretBytes` (binding contract)

`public struct SecretBytes: ~Copyable, Sendable` backed by a page-aligned `mmap` region with `mlock`, wiped with `memset_s` in `deinit`. Ratified 25 October 2026: `mlock` is best effort; allocation succeeds when locking fails and `isLocked` reports it, because sandboxed extensions can hit the locked-memory limit and refusing to hold a key at all would be worse than holding it unlocked. It conforms to neither `Codable` nor `CustomStringConvertible`. Explicit `encode(into: inout SecretBytes)` / `init(parsing: borrowing SecretBytes)` functions move key material between containers. Secrets never become `String`; the parser works on UTF-8 byte views and overwrites mutable input buffers after parsing. Copies made by Foundation, XPC and the Go heap are transient and are not zeroised; the contract is "minimise and bound", not "guarantee". The daemon calls `setrlimit(RLIMIT_CORE, 0)` at startup.

### Validation and diagnostics

```swift
public struct ConfigDiagnostic: Sendable, Hashable, Codable {
    public enum Severity { case error, warning }
    public enum Code: String { case unknownKey, forbiddenHook, amneziaField, duplicateKey, duplicatePeer, invalidCIDR,
        invalidKey, invalidEndpoint, invalidPort, invalidMTU, limitExceeded, controlCharacter, dnsOutsideAllowedIPs,
        noAddresses, noPeers, ipv6PolicyRequired, keyInUseElsewhere, carrierRequiresSinglePeer, keepaliveClampedByCarrier }
    public var severity: Severity; public var code: Code; public var line: Int?; public var message: String
}
public func parseWgQuick(_ bytes: borrowing [UInt8], limits: ParseLimits = .default) throws(ConfigParseError) -> ParsedConfiguration
public func serialiseWgQuick(_ profile: TunnelProfile, secrets: borrowing SecretBundle?) -> SecretText   // SecretText is a ~Copyable byte buffer when secrets are present
```

### Public statistics DTO

```swift
public struct TunnelStatistics: Codable, Sendable, Hashable {
    public var generation: UInt64
    public var sampledAt: Date
    public var interfaceName: String?
    public var listenPort: UInt16?
    public var peers: [PeerStatistics]
}
public struct PeerStatistics: Codable, Sendable, Hashable {
    public var publicKey: PublicKey
    public var endpoint: Endpoint?                // engine-observed (roaming) endpoint
    public var lastHandshake: Date?               // wall clock from the engine
    public var rxBytes: UInt64, txBytes: UInt64
    public var persistentKeepalive: UInt16?
}
```

The engine's `wgex_public_stats_json` filters secrets; the Swift decoder rejects any `private_key`/`preshared_key` key as a second guard.

### Seam protocols (defined in phase 0, P0-16)

```swift
public protocol TunnelBackend: Sendable {
    var capabilities: BackendCapabilities { get }
    func install(_ profile: TunnelProfile) async throws(TunnelError)
    func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError)
    func start(_ id: UUID, transport: TransportID?) async throws(TunnelError)
    func stop(_ id: UUID) async throws(TunnelError)
    func statusUpdates() -> AsyncStream<TunnelStatus>
    func statistics() async throws(TunnelError) -> TunnelStatistics
}
public protocol EngineControlling: Actor { /* mirrors EngineActor's API in §6.4 */ }
public protocol ServiceControlling: Sendable { var state: AsyncStream<ServiceState> { get }; func register() async throws; func unregister() async throws; func openApproval() }
public protocol RouteProgramming, DNSConfigurating, PolicyEnforcing, UnderlayResolving { /* daemon ports with fakes in WGEXTesting */ }
```

## 4. Status and state machines

### 4.1 Tunnel lifecycle (shared vocabulary)

```swift
public enum TunnelPhase: Codable, Sendable, Hashable {
    case idle
    case preparing(Generation)                  // resolving endpoints, choosing underlay
    case configuring(Generation)                // interface up, routes/DNS/settings being applied
    case active(Generation)                     // settings verified; engine running
    case reasserting(Generation, reason: ReassertReason)   // path change, wake, transport switch
    case captiveWindow(Generation, expires: Date)          // Mac only; routes and DNS withdrawn, pf pass-out
    case stopping(Generation, reason: StopReason)
    case failed(TunnelError, blockedByPolicy: Bool, needsSecrets: Bool)
}
public struct TunnelHealth: Codable, Sendable, Hashable {
    public enum Level { case healthy, idle, degraded(reason: String), unresponsive, offline }
    public var level: Level; public var lastHandshake: Date?; public var rxRate: Double; public var txRate: Double
}
public struct TunnelStatus: Codable, Sendable, Hashable {
    public var phase: TunnelPhase
    public var protection: ProtectionState      // ADR-009
    public var transport: TransportID?
    public var health: TunnelHealth
    public var recentEvents: [TunnelEvent]      // bounded to 32 on every platform
}
```

Health is driven by **engine events**, not by UI sampling: the engine reports `txWithoutRx(since:)` when data or a handshake initiation was sent and nothing came back within `KeepaliveTimeout + RekeyTimeout` (15 s), `handshakeCompleted`, `rx`. Level rules (`WGEXPolicy.HealthEvaluator`): `idle` = no tx for 60 s and no failure; `degraded` = one 15-s window of tx without rx; `unresponsive` = two consecutive windows; `offline` = path unsatisfied. Before an idle tunnel can be judged unresponsive it is probed with `forceHandshake` and given 2 × RekeyTimeout. "Connected, idle" is a display state, never an error.

### 4.2 Mac `TunnelController` (daemon actor)

States: `Idle → Preparing → Configuring → Active ⇄ Reasserting → Stopping → Idle`, plus `CaptiveWindow` (from Active/Reasserting/Error while intent is up), `Error` (blocking if intent is up or lockdown) and the global `Lockdown` flag. The controller serialises all mutations. **Generations are allocated by the daemon**, returned in the `start` reply; a newer generation cancels in-flight work through `Task` cancellation and the journal's generation check. Exactly one profile may be intended-up in v1 (`TunnelError.anotherTunnelActive`).

**Start contract** for `start(profileID, secrets)`:
1. Validate the registered profile again (defence in depth) and store the secrets in the daemon secret store (ADR-008: intended-up secrets persist until explicit disconnect or removal, so a crashed daemon can recover without the app).
2. pf → `connecting(resolvers: underlay resolvers, endpoints: [])`: block all, allow loopback, DHCP/NDP, LAN per global setting, and **root DNS to the underlay's resolvers only**.
3. Resolve endpoints with the `UnderlayResolver` (§7.5): root sockets bound with `IP_BOUND_IF`/`IPV6_BOUND_IF` to the underlay, resolvers from `State:/Network/Service/<primary>/DNS`; last-known-good addresses from the journal are tried first and used as fallback. Candidates are ordered per RFC 8305 (IPv6 first only when the underlay has an IPv6 primary).
4. pf → `connecting(resolvers, endpoints: all candidates)`.
5. `EngineActor` create (`tun_kind = 2`, bind interfaces = underlay v4/v6 indexes), `setConfiguration` (first candidate per peer), `up`.
6. Addresses and MTU (`CWGEXSysShim` ioctls), routes (`/1` pairs or AllowedIPs; tagged `RTF_PROTO2`), DNS key (§7.3).
7. Verify: routes present (`RTM_GET`), DNS key present and resolver order as expected, pf anchor loaded and evaluation canary hit, engine alive. Only now `Active`; pf → `connected(tun, endpoints)`; interface-scoped state kill on the underlay (§7.4).
8. Journal `commit(generation)`.

Endpoint candidate rotation: if no handshake completes within 2 × RekeyTimeout of the first initiation, advance to the next candidate via `updateEndpoints` (partial UAPI, no session loss); when all candidates fail, back off (5 s → 60 s) and re-resolve. Re-resolution happens on path change, on all-candidates failure and on user action, never on a timer while handshakes succeed. The pf endpoint set always contains all current candidates and is updated atomically before any switch.

On failure between 2 and 7: undo in reverse order only what this generation installed, keep pf in `error` (blocking) if intent is still up, report `failed(error, blockedByPolicy: true, needsSecrets: false)`.

**Stop contract** for `stop(profileID, reason)` (journalled per step; each step is a crash-matrix point):
1. If lockdown or intent remains (system-initiated stop), pf → blocking policy **without** the tun pass; otherwise pf → `disconnecting` (blocking) for the duration of teardown.
2. Remove the DNS key.
3. Remove the `/1` and AllowedIPs routes this generation owns.
4. Engine down and destroy (the utun disappears with it).
5. pf → `disconnected` or `lockdown`; release the pf enable token if nothing else needs pf (journal records the token).
6. Interface-scoped state kill on the underlay.
7. Delete the daemon-store secrets if the stop was an explicit user disconnect; keep them if intent remains.

**Reconciliation at daemon start**: first action is to replace any persisted `connected` policy with `error` (no tun pass; a utun name may have been reused by another product); then inspect reality (routes with `RTF_PROTO2` and journalled identity, DNS key, pf references via `pfctl -s References`, utun existence by journalled `if_index` plus creation identity), remove only what is ours, close an expired captive window, then apply lockdown and intended-up/start-before-login intents (secrets from the daemon store; if absent, `failed(needsSecrets: true)` blocking and a notification "Open WGEX to reconnect").

**Status publication (as built, 26 October 2026; revision 3 target in M1-03).** The controller publishes `TunnelStatus` on every phase or protection edge and, since 26 October, republishes the current status from the 5 s tick while idle so the client's staleness clock (10 s) is not tripped at rest. Gaps the audit recorded: the heartbeat is skipped while an operation is in flight or while secure install is pending; `TunnelStatus` carries neither a daemon sequence number nor the active profile ID, so the client stamps receipt time as measurement time and guesses the active tunnel from its selection. Revision 3 target: a daemon-side monotonic `sequence`, `activeProfileID` and `measuredAt` on every status; a heartbeat timer in the dispatcher independent of operations; the client treats a missed heartbeat as `unknown(.notReporting(since:))` while XPC is still connected and as `stale` after invalidation.

**Startup failure (as built).** `reconcileAtStartup()` runs before the listener exists; any error exits 78 and launchd (`KeepAlive.SuccessfulExit=false`) respawns the daemon about every 10 s, each attempt re-enabling pf. Revision 3 target (M1-02): bounded retries with a degraded, listener-up "blocked, needs repair" mode so the app can show the reason and the admin can repair; a pf enable reference is journalled as *attempted* before `-E` so a crash between `-E` and the parse can be reconciled from `-s References`.

### 4.3 NE `ProviderController` (extension actor)

`startTunnel(options)`: load the profile by ID from the app-group store; fetch secrets from Keychain; resolve endpoints with `Network.framework` parameters that **require the physical interface** (`requiredInterfaceType` / `prohibitedInterfaceTypes: [.other]`) before `setTunnelNetworkSettings`; generate settings (§9); apply with a 10 s deadline (timeout = failure); obtain the utun descriptor via `wgex_find_utun_fd` (Go); `EngineActor` create (`tun_kind = 0`, mtu 0), configuration, up; on iOS/tvOS call the engine's `DisableSomeRoamingForBrokenMobileSemantics` after every apply; start the path monitor; phase `active`. `stopTunnel(reason)`: engine down, `setTunnelNetworkSettings(nil)` under `withTaskCancellationShield`, record the stop reason by its SDK name (raw 17 is `internalError`; corrected 25 October 2026). `sleep()` records `mach_continuous_time` and quiesces timers only (never `down`); `wake()` bumps sockets and forces a handshake when the wall-clock handshake age exceeds 110 s or the sleep delta exceeds 5 s, with `reasserting` until the next handshake. Path change: re-resolve, `updateEndpoints`, bump sockets; unsatisfied for more than 30 s → quiesce; satisfied → resume. Stats: produced on request from the app and on a 30-s internal tick only for health bookkeeping; the UI-facing stream runs at 2 s while subscribed.

## 5. Mac XPC protocol (`WGEXDaemonProtocol`)

Transport: `NSXPCConnection` to Mach service `BuildIdentifiers.daemonService` (= `<WGEX_BUNDLE_ID_BASE>.daemon`), opened by the client with `options: .privileged` (system domain). Reply blocks are one-shot, so events flow over a **client-exported interface**:

```swift
@objc public protocol WGEXDaemonXPC {
    func send(_ envelope: Data, reply: @escaping (Data) -> Void)
    func start(_ envelope: Data, secrets: Data, reply: @escaping (Data) -> Void)              // secrets in the wire layout below, never inside the envelope
    func setStartBeforeLogin(_ envelope: Data, secrets: Data, reply: @escaping (Data) -> Void)
    func subscribe(_ envelope: Data, reply: @escaping (Data) -> Void)                        // replies once with an ack; events arrive on the client's exported object
}
@objc public protocol WGEXClientEventsXPC {
    func event(_ data: Data)                                                                 // daemon → client via remoteObjectProxyWithErrorHandler; subscriber dropped after 32 undelivered events
    func provideSecrets(_ request: Data, reply: @escaping (Data) -> Void)                    // daemon → app: used only when the CLI asks to start a profile whose secrets are not in the daemon store
}
```

Envelope encoding: `PropertyListEncoder` (binary), never JSON. `Envelope { protocolVersion: 7, requestID: UUID, authorization: Data? /* AuthorizationExternalForm */, body: Request }`; the version is exact-match (a mismatch is rejected before decoding the body).

```swift
public enum Request: Codable, Sendable {
    case hello(clientVersion: String, clientBuild: Int)
    case installProfile(DaemonProfile)                                  // idempotent by (id, revision); owner uid recorded from the connection
    case removeProfile(UUID, purgeSecrets: Bool)
    case startIntent(profileID: UUID, transport: TransportID?, hasSecrets: Bool)   // carried by the `start` method; reply contains the daemon-allocated Generation
    case stop(profileID: UUID, reason: StopReason)
    case stopCurrent(reason: StopReason)                                // whatever is intended-up for the caller; no profile ID needed
    case selectTransport(profileID: UUID, transport: TransportID?)      // nil = automatic
    case setGlobalSettings(MacGlobalSettings)
    case openCaptiveWindow(seconds: Int), extendCaptiveWindow(seconds: Int), closeCaptiveWindow
    case subscribeEvents(includeLogs: Bool)                             // carried by the `subscribe` method
    case secureInstallStatus                                             // any verified client
    case performSecureInstall                                            // admin right; see §7.9
    case setStartBeforeLoginIntent(profileID: UUID, enabled: Bool)      // carried by the `setStartBeforeLogin` method when enabling
    case status, statistics
    case logs(since: Date?, limit: Int)
    case diagnostics(DiagnosticsRequest)
    case prepareForUpdate                                                // exits after reply; accepted only from a client whose build is newer
    case uninstall(purgeState: Bool)
}
public enum Reply: Codable, Sendable { case hello(HelloReply), ok, started(Generation), status(TunnelStatus), statistics(TunnelStatistics), logs([RedactedLogLine]), diagnostics(DiagnosticsBundle), secureInstall(SecureInstallState), error(DaemonError) }
public enum Event: Codable, Sendable { case status(TunnelStatus), statistics(TunnelStatistics), log(RedactedLogLine), needsSecrets(profileID: UUID) }
public struct DaemonProfile: Codable, Sendable { public var profile: TunnelProfile /* secrets refs .daemonStore only */; public var revision: UInt64 }
```

**Secrets wire layout** (`Data` argument): `u8 version=1 | 32 B private key | u16 count | count × (32 B peer public key | 32 B PSK) | u16 carrierCount | carrierCount × (16 B transport id | u16 len | bytes)`. The client writes it into an `UnsafeMutableRawBufferPointer`, wipes it with `memset_s` after the call returns; the daemon parses into `SecretBytes` and wipes its copy. The envelope carries only `hasSecrets`.

**Authentication.** The daemon calls `listener.setConnectionCodeSigningRequirement(R)` once before `resume()` (connections failing it are rejected before the delegate runs) **and** `newConnection.setCodeSigningRequirement(R)` in `shouldAcceptNewConnection` so every message is checked. The client sets the daemon requirement on its connection before `resume()` and sends secrets only after a successful `hello`. Requirement strings are compile-time constants generated from `BuildIdentifiers`:

- Release (client → daemon and daemon → client, identifiers swapped): `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "<team id>" and (identifier "<base>.daemon") and !(entitlement["com.apple.security.get-task-allow"] exists)` (daemon side accepts `identifier "<base>" or identifier "<base>.cli"`).
- Debug: `anchor apple generic and certificate leaf[subject.OU] = "<team id>" and (identifier …)` with the `.dev` base; Debug and Release use different Mach service names (`.dev.daemon` versus `.daemon`) so they can never talk to each other.
- A unit test creates every string with `SecRequirementCreateWithString` (a malformed string is an uncatchable exception at runtime) and asserts the Debug constants contain `.dev` and the Release ones do not. The macOS 26 Swift XPC overlay was evaluated and rejected: `XPCReceivedMessage` exposes no peer uid or audit session.

**Authorisation table** (daemon-side; uid and audit session from the connection, never from the body):

| Request | Rule |
|---|---|
| `installProfile`, `removeProfile`, `status`, `statistics`, `logs`, `diagnostics` | Owner uid only; cross-uid requests are rejected (no `manage-any` right in v1); logs and diagnostics are filtered to the caller's profiles plus redacted global events |
| `start`, `selectTransport`, `openCaptiveWindow` | Owner uid **and** console user (`SCDynamicStoreCopyConsoleUser` matches the connection's audit session), or root |
| `stop` | Owner uid |
| `setGlobalSettings` (lockdown off, allowLAN on, captive seconds), `prepareForUpdate`, `uninstall` | Admin right `com.magrathean.WGEXApp.manage-protection` (class `rule` delegating to `authenticate-admin-nonshared`: admin, not shared, 30 s; M01-T02) obtained by the client with `AuthorizationCopyRights` and verified in the daemon from the external form; `prepareForUpdate` additionally requires `clientBuild > daemonBuild` |
| `setGlobalSettings` (lockdown on, allowLAN off) | Owner uid and console user (tightening needs no admin) |

Limits: envelope ≤ 256 KiB (as built; the 1 MiB figure of revision 2 was never needed), one in-flight `start`/`stop` per profile, 16 subscriptions per uid, 64 requests per second per connection, 32 queued events per subscriber (overflow drops the subscription; revision 3 adds a `subscriptionLost` event so the client resubscribes, M1-03). Install revisions: as built the client allocates `max(previous + 1, wall-clock ms)`; revision 3 moves allocation into the daemon (reply carries the accepted revision, compare-and-swap on install) because a clock step or two concurrent clients can wedge a profile behind `staleRevision` (M1-04).

**Anti-rollback.** The daemon keeps `/Library/Application Support/WGEX/min-build` (root-owned) with the highest build it has run; a daemon whose build is lower exits with a logged reason and the app shows "downgrade detected". `hello` from a client with `clientBuild < minClientBuild` (compiled into the daemon) is rejected. Explicit downgrade: `wgex downgrade --allow` with the admin right lowers the floor.

### 5.1 On-demand (ADR-030, protocol 8)

On macOS the daemon evaluates on-demand rules (ADR-030 section 1); nothing in the system does it for a launch daemon (ADR-003), and the app never connects or disconnects for a rule. `OnDemandCompiler` (WGEXPolicy) compiles a profile's policy to ordered rules, a pure `OnDemandEvaluator` maps rules plus network context to connect, disconnect or hold, and `OnDemandCoordinator` (WGEXDaemonCore) runs it on path changes and drives `TunnelController`. The SSID cannot be read by a launch daemon, so the app, which can hold Location authorisation, relays it: the daemon asks with `Event.wifiNetworkRequested` and the app answers with `Request.reportWiFiNetwork` (new policy `consoleUserApp`). Without SSID access an exclude list skips its disconnect rule, so the tunnel connects, and an include list holds the current state (ADR-030 section 4). Protocol 7 moves to 8 with `armOnDemand`, `disarmOnDemand` and `reportWiFiNetwork`; the implementation uses the admission fences, epoch and durable selection described in the ADR-030 structural addendum.

## 6. Go engine and bridge (`Engine/go`)

### 6.1 Package layout

```
Engine/go/
  go.mod                      module github.com/magrathean-uk/wgex/engine; go 1.27; toolchain go1.27.3; vendored deps committed
  bridge/                     package main (required by -buildmode=c-archive); //export wgex_*; wgex.h (module CWGEXEngine)
  engine/                     package engine: Engine (device, tun, SwitchBind, stats, events), memgov
  engine/stats.go             public stats from device.IpcGet, filtered → JSON
  tun/darwin_fd.go            tun_kind 0: tun.CreateTUNFromFile on an NE utun descriptor (mtu 0)
  tun/packetfd.go             tun_kind 1: SOCK_DGRAM socketpair end, one raw IP packet per datagram, no AF header (tests and packetFlow fallback)
  tun/darwin_create.go        tun_kind 2: root-only utun creation
  tun/findfd_ios.go           wgex_find_utun_fd: descriptor scan with unix.IoctlCtlInfo (GOOS=ios)
  resolver/                   UnderlayResolver: DNS client over sockets bound with IP_BOUND_IF/IPV6_BOUND_IF (A/AAAA, TCP fallback, DoH fallback to a pinned IP optional)
  transport/switchbind.go     SwitchBind: the only conn.Bind ever given to device.NewDevice (§8.2)
  transport/udp/              inner transport: one unconnected socket per family, bound to the underlay interface via a Control hook (copy of StdNetBind + Control)
  transport/vless/            inner transport: stream carrier adapter with VLESS framing
  carrier/wstls/              coder/websocket + utls (ALPN forced to http/1.1)
  testsupport/                //go:build wgextest: netstack pairs, wgex_test_* exports; built only into WGEXEngineTest.xcframework (macOS slice) for Swift tests
  cmd/wgex-engine-test/       Go-side integration binary
```

Build flags in `build-xcframework.sh`: `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off`, `-trimpath`, `-ldflags "-w -X main.appVersion=… -X main.build=… -X main.scriptSHA=…"` plus `-macos=26.0 -macsdk=27.0` on the macOS slice (ADR-002 amendment); `verify-slices.sh` checks every archive member including `go.o`. Production archives must contain no `_wgex_test_` symbols and no `gvisor.dev` module (`go version -m`).

### 6.2 C ABI (`Engine/go/bridge/wgex.h`)

```c
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef int64_t wgex_handle;                 // > 0 valid; < 0 error code
typedef enum { WGEX_OK = 0, WGEX_EINVAL = -1, WGEX_ENOMEM = -2, WGEX_EHANDLE = -3, WGEX_ETUN = -4,
               WGEX_EBIND = -5, WGEX_ECONFIG = -6, WGEX_EUP = -7, WGEX_ESTATE = -8, WGEX_EINTERNAL = -99 } wgex_error_t;
typedef void (*wgex_log_fn)(void *ctx, int32_t level, const char *msg, size_t len);     // msg not NUL-terminated; copy immediately
typedef void (*wgex_event_fn)(void *ctx, int32_t kind, const char *json, size_t len);  // engine/health/transport events

typedef struct {
    int32_t     tun_kind;          // 0 = NE utun fd (mtu must be 0), 1 = packet fd (socketpair), 2 = create utun (root)
    int32_t     tun_fd;            // for kinds 0 and 1
    const char *tun_name;          // kind 2: "utun" (auto-assign); NULL otherwise
    int32_t     mtu;               // kinds 1 and 2
    int32_t     bind_ifindex_v4;   // 0 = unbound
    int32_t     bind_ifindex_v6;   // 0 = unbound
    const char *transport_json;    // TransportSpec; {"kind":"udp"} default
    int32_t     mobile_quirks;     // 1 on iOS/tvOS: DisableSomeRoamingForBrokenMobileSemantics after each apply
    wgex_log_fn log;   void *log_ctx;
    wgex_event_fn event; void *event_ctx;
} wgex_create_params;

/* Process-wide settings; applied by the first wgex_create in the process, later calls with different values return WGEX_ESTATE.
   queue_profile is ignored on macOS (wireguard-go queue sizes are consts there). */
typedef struct { int64_t memory_limit_bytes; int32_t gc_percent; int32_t queue_profile; } wgex_process_params;
int32_t      wgex_configure_process(const wgex_process_params *p);

wgex_handle  wgex_create(const wgex_create_params *p);
int32_t      wgex_set_config(wgex_handle h, const uint8_t *uapi, size_t len);        // full replace (replace_peers=true); parsed from bytes, never converted to a Go string; previous config restored on error
int32_t      wgex_update_endpoints(wgex_handle h, const uint8_t *uapi, size_t len);  // only public_key / update_only=true / endpoint lines; no session loss
int32_t      wgex_up(wgex_handle h);
int32_t      wgex_down(wgex_handle h);
int32_t      wgex_destroy(wgex_handle h);                                             // drains callbacks; returns only after no callback is in flight
int32_t      wgex_bump_sockets(wgex_handle h, int32_t ifindex_v4, int32_t ifindex_v6); // rebind UDP inner transport; cancels a previous attempt
int32_t      wgex_set_transport(wgex_handle h, const char *transport_json, size_t len); // swaps SwitchBind's inner transport; never blocks on network
int32_t      wgex_force_handshake(wgex_handle h);                                     // per peer: ExpireCurrentKeypairs + SendHandshakeInitiation; no peer replacement
int32_t      wgex_find_utun_fd(void);                                                 // iOS/tvOS: descriptor scan; -1 if none
char        *wgex_public_stats_json(wgex_handle h);                                   // caller frees with wgex_free
const char  *wgex_tun_name(wgex_handle h);
int32_t      wgex_free_os_memory(void);
void         wgex_free(void *p);
const char  *wgex_build_info(void);                                                   // static JSON {app_version, build, engine_commit, go, script_sha}
```

Rules: no function blocks on the network; callbacks run on Go threads (unknown executor); `wgex_destroy` waits for callback drain with a `WaitGroup`; registry under `sync.Mutex`; no package-global logger; no signal handlers; `wgex_set_config` keeps the last good document and re-applies it when `IpcSet` fails.

### 6.3 Memory governor

Constrained profile (extensions): `device.QueueOutboundSize = 256`, `QueueInboundSize = 256`, `QueueHandshakeSize = 256`, `PreallocatedBuffersPerPool = 256` (vars under the `ios` tag), `debug.SetMemoryLimit(24 MiB)`, `debug.SetGCPercent(50)`, `FreeOSMemory` on the Swift memory-pressure source. Numbers are tuned by P1-13/P1-15 measurements.

### 6.4 Swift `EngineActor`

```swift
public actor EngineActor: EngineControlling {
    public init(configuration: EngineConfiguration) throws(EngineError)   // calls wgex_create; wgex_configure_process first if needed
    public func setConfiguration(_ uapi: borrowing UAPIDocument) throws(EngineError)
    public func updateEndpoints(_ updates: [PublicKey: Endpoint]) throws(EngineError)
    public func up() throws(EngineError); public func down() throws(EngineError)
    public func bumpSockets(v4: UInt32?, v6: UInt32?) throws(EngineError)
    public func setTransport(_ spec: TransportSpec) throws(EngineError)
    public func forceHandshake() throws(EngineError)
    public func statistics() throws(EngineError) -> TunnelStatistics
    public var logs: AsyncStream<EngineLogLine> { get }
    public var events: AsyncStream<EngineEvent> { get }                  // includes health events (txWithoutRx, handshakeCompleted, rx) and transport events
    public func shutdown() async                                            // wgex_destroy; idempotent
}
```

`UAPIDocument` (owned by `WGEXCore`, P2-05) is a `~Copyable` byte buffer produced by `UAPIEncoder` (`replace_peers=true` for full documents, hex keys, literal endpoints) and wiped after the call. The daemon and providers link `WGEXEngine`; everything else talks to `EngineControlling` so `FakeEngine` can stand in.

## 7. macOS network ownership (`WGEXDaemonCore`)

### 7.1 `UTunDevice`
Created by the engine (`tun_kind = 2`); the daemon reads the name back and the index via `if_nametoindex`, and records the creation identity (index plus `ifi_lastchange`) in the journal. Addresses via `CWGEXSysShim` (`SIOCAIFADDR`, `SIOCAIFADDR_IN6`), MTU via `SIOCSIFMTU`.

### 7.2 `RouteTable` and `UnderlayMonitor`
`PF_ROUTE` socket, `RTM_ADD/RTM_DELETE/RTM_GET/RTM_CHANGE` with sequence numbers and reply parsing. Every WGEX route carries `RTF_PROTO2` as an ownership mark in addition to the journal; deletion requires a journal entry, `RTF_PROTO2` present, and the journalled interface identity. Full tunnel uses the `/1` pairs (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`); split tunnels use AllowedIPs routes. **There are no endpoint escape routes.** Loop prevention is `IP_BOUND_IF`/`IPV6_BOUND_IF` on every engine, carrier and resolver socket (Tailscale's model); a lab test proves WireGuard UDP never appears on the utun and that sends fail cleanly when the underlay is down. The underlay is read from `State:/Network/Global/IPv4` and `/IPv6` → `PrimaryInterface` (per family, with notifications), with `NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])` as a secondary signal. The route monitor consumes `RTM_IFINFO/NEWADDR/DELADDR/ADD/DELETE` (filtered to non-self pid), debounced 300 ms, and re-adds missing `/1` routes, re-selects the underlay and rebinds (`bumpSockets(v4:v6:)`). MTU is recomputed on every underlay change: `min(profile override, underlay MTU − 80, 1420 when a carrier is active, 1500)` and applied live.

### 7.3 `DNSConfigurator`
Daemon-owned `SCDynamicStore` session for the daemon's lifetime. Full tunnel: a single key `State:/Network/Service/<WGEX-UUID>/DNS` = `{ServerAddresses, SearchDomains, SupplementalMatchDomains: [""], SearchOrder: <value fixed by P4-04>}` created with `SCDynamicStoreAddTemporaryValue` (an empty supplemental match domain makes the entry a default resolver; this is Tailscale's shipping pattern). Split DNS: `SupplementalMatchDomains: [domains]`. No IPv4 entity, no `OverridePrimary`, no non-schema keys. Updates are `SCDynamicStoreRemoveValue` followed by `AddTemporaryValue` on the same session under the controller actor. Verification parses the resolver list obtained with the read-only external `/usr/sbin/scutil --dns` (the only external process besides `pfctl`): the WGEX servers must appear first for the empty domain. Fallback mode if P4-04 fails: journalled `Setup:/Network/Service/<id>/DNS` writes with conditional restoration (Mullvad's model). Non-tunnel DNS is additionally blocked by pf while protected.

### 7.4 `PacketFilter`
Typed rule model → anchor text → `/sbin/pfctl` (`Process` with fixed path, argv array, cleared environment, 10 s deadline, both pipes drained). Binding rules:

- The renderer never emits `set` lines (options are ignored inside anchors). Every rule is `quick`. The last rule is `block drop quick all`.
- Enable with a reference token (`pfctl -E`, token parsed from stderr and **journalled** before any rule load); release with `-X <token>` on `disconnected` without lockdown; reconciliation reads `pfctl -s References` and adopts or releases only journalled tokens; at most one WGEX token at a time.
- Load with `pfctl -o none -a com.apple/wgex -f -` (rules on stdin; `-o none` because the default optimiser drops rules it considers subsets and reorders `quick` rules, so the read-back never matched); verify with `pfctl -a com.apple/wgex -sr` parsed against the model; dry-run with `-n` first.
- pfctl output drifts between OS releases (RISK-27): macOS 26 prints `Token : N` for `-E` where 15 printed `Token: N`, and `-s References` is a table (PID, process, TOKEN, TIMESTAMP). Parsers accept both forms and keep a golden transcript per release.
- Lab builds only (`WGEX_LAB_BUILD`): two stateful `pass` rules for TCP/22 from the vmnet host keep the lab's SSH alive through blocking phases (`PFContext.labEscapeHatch`). A blocking ruleset otherwise strands the guest. Production never sets it; every lab leak verdict records the exception; revision 3 compiles the field out of Release (M1-01).
- **States are never flushed globally.** On entering `connecting`, `connected` or `lockdown`: `pfctl -i <underlay> -F states` (P4-06 verifies in the VM that `-i` restricts the flush; fallback is `-k`-based host kills). Never on captive or disconnect.
- Stock anchor check: the main ruleset must contain `anchor "com.apple/*"`; otherwise protection is `unknown` and no kill switch is claimed. Evaluation order and sibling anchors are recorded per macOS release (`pfctl -a com.apple -s Anchors -v`).
- Evaluation canary: a counting rule for root UDP to `192.0.2.1:9` on the underlay; the liveness monitor (P4-23) sends one datagram and checks the counter with `pfctl -a com.apple/wgex -vsr` at daemon start, after every macOS build change, on configd/route notifications, and every 5 s while any blocking policy is active. No increment, pf disabled (`pfctl -d` by someone), or a changed anchor → `unknown`, re-enable and reload.

Rule order (connected policy; `<ulay>` = underlay interface, `<tun>` = utun; endpoints and resolvers from the controller):

```
pass quick on lo0 all
pass out quick on <tun> all
pass in quick on <tun> all
pass out quick on <ulay> proto udp from any to <endpoint-ip> port <endpoint-port> user root keep state      # per endpoint candidate
pass out quick on <ulay> proto tcp from any to <carrier-ip> port <carrier-port> user root keep state        # per carrier bootstrap address (phase 6)
pass out quick on <ulay> proto {udp tcp} from any to <underlay-resolver-ip> port 53 user root keep state    # UnderlayResolver only
pass out quick on <tun> proto {udp tcp} to <tunnel-dns-ip> port 53                                          # explicit; a LAN tunnel DNS gets a pass on <ulay> here, nowhere else
block drop out quick proto {tcp udp} from any to any port {53 853}                                          # DNS block precedes every LAN pass (golden-test asserts the index)
pass out quick on <ulay> proto udp from any port 68 to {255.255.255.255, (<ulay>:network)} port 67
pass in  quick on <ulay> proto udp from any port 67 to any port 68
pass out quick on <ulay> inet6 proto udp from fe80::/10 port 546 to ff02::1:2 port 547
pass in  quick on <ulay> inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546
pass quick on <ulay> inet6 proto icmp6 from {fe80::/10, ::} to {fe80::/10, ff02::/16} icmp6-type {133,134,135,136}   # no redirect (137)
pass in quick on <ulay> inet6 proto icmp6 from <endpoint-ip6> icmp6-type 2                                 # packet too big, endpoint flow only
pass in quick on <ulay> inet proto icmp from <endpoint-ip4> icmp-type unreach code needfrag
block drop out quick on <ulay> to <wgex_tunnel_ranges>                                                      # table: AllowedIPs minus 0/0 and ::/0, tunnel DNS, interface addresses; prevents tunnel-bound traffic reaching the LAN while the tunnel is down
pass quick on <ulay> from (<ulay>:network) to (<ulay>:network)                                              # allowLAN: this interface's own subnet only, plus:
pass quick on <ulay> from any to {169.254.0.0/16, 224.0.0.0/24, 255.255.255.255, fe80::/10, ff02::/16}
block drop quick all
```

`connecting` = the same without the `<tun>` passes; `error` = `connecting` without endpoint passes; `lockdown` = `error`; `disconnected` = anchor emptied (unless lockdown). Captive window (§7.7) adds `pass out quick on <ulay> proto tcp from any to any port {80 443} user <console uid>` and `pass out quick on <ulay> proto {udp tcp} to <dhcp-resolvers> port 53` and withdraws routes and DNS. `route-to` for Apple services bypassing routing is a version-gated addition decided by P4-18. Every policy has a golden file and a lab verdict.

### 7.5 `UnderlayResolver`
Go package `resolver` exposed through the bridge (`wgex_resolve(host, ifindex_v4, ifindex_v6, resolvers_json) → json`), used by the daemon for endpoint and carrier bootstrap resolution under blocking policies and for all re-resolution. Queries go from root sockets bound to the underlay to the resolvers configd lists for the primary service; TCP fallback; results cached with TTL and persisted (last-known-good) in the journal. mDNSResponder is never relied upon while blocking.

### 7.6 `PowerMonitor` and `LoginSessionMonitor`
IOKit sleep/wake per §4.3 wake rule plus route/DNS/pf re-verification; `SCDynamicStoreCopyConsoleUser` notifications implement ADR-026 (stop non-start-before-login tunnels at logout, remember intent, resume on the owner's next `start`).

### 7.7 Captive window
A journalled sub-state (`captiveWindow{expiresAtContinuous, expiresAtWall}`): removes the DNS key, withdraws the `/1`/AllowedIPs routes (engine stays up), loads the narrowed pass rules, starts a `mach_continuous_time` timer. Close or expiry restores pf blocking first, then routes, DNS key and `connected`. Reconciliation (daemon restart, wake) closes an expired or undetermined window immediately. Known gap: the pass rules persist in the kernel while the daemon is dead.

### 7.8 `Journal`
`/Library/Application Support/WGEX/journal.json`, atomic replace, schema-versioned. As built (`DaemonJournal.swift`): a write-ahead log of `(generation, DaemonStep, willApply | didApply | undo | didUndo)` entries (steps from `validateSecrets` through `commit`, the stop steps, and the reconciliation steps), plus per-generation `GenerationResources` (attempted steps, `TunnelIdentity{name, if_index, creationID}`, addresses, route flags, routes, DNS configuration and key), the pf token and policy, the captive window record (wall and continuous deadlines) and the persisted intents. Entries are capped at 4096 and the whole document is re-encoded on every mutation (about 270 KB with two fsyncs; revision 3 trims entries to the current and previous generation, M1-05). Reconciliation rules are in §4.2.

### 7.9 Secure install and bundle integrity (ADR-025)
After approval the daemon verifies the bundle's designated requirement, then performs the **secure install**: `chown -R root:wheel` and `chmod -R go-w` on `/Applications/WGEX.app`; it refuses privileged operations while any file in the bundle is writable by a non-root user, and the app shows "Secure install needed" with a one-click action. Sparkle is configured for root-owned installs (authorised installer). Bundle self-validation is an integrity check for accidents, not a security boundary.

### 7.10 macOS 26 fallbacks

The deployment floor is macOS 26.0 (ADR-002 amendment); iOS and tvOS remain 27.0. Xcode 27.2, Swift 6.4 in Swift 6 mode, warnings as errors and the installed 27 SDK remain required. The engine macOS slice targets `arm64-apple-macos26.0`; the other four slices keep their 27.0 targets.

| API | Where | macOS 26 behaviour | Protection impact |
| --- | --- | --- | --- |
| None identified by compilation | App, daemon, CLI and package targets | Existing API paths; no availability fallback introduced | No protection control weakened; runtime acceptance on 27 is pending (RISK-25) |

The legacy `SecKeychainOpen` call remains isolated in the key-provider method under its deprecation annotation. It is not a 27-only API. macOS 26 runtime testing, including the pf and DNS matrix, runs in the Tahoe guest; the 27 matrix must be rerun before the owner cutover.

## 8. Transport layer (phase 6)

### 8.1 Profile schema

```swift
public struct TransportPolicy: Codable, Sendable, Hashable {
    public var candidates: [TransportCandidate]       // ordered; `.udp` first by default
    public var selection: TransportSelection          // .manual(TransportID) | .automatic(FailoverPolicy)
}
public struct TransportCandidate: Codable, Sendable, Hashable, Identifiable { public var id: TransportID; public var name: String; public var spec: TransportSpec }
public enum TransportSpec: Codable, Sendable, Hashable {
    case udp
    case vlessReality(VLESSRealitySpec)
    case vlessWebSocketTLS(VLESSWebSocketSpec)
}
public struct VLESSRealitySpec: Codable, Sendable, Hashable {
    public var server: BootstrapAddress        // numeric IP(s) + port, optional hostname for refresh through UnderlayResolver
    public var uuidRef: SecretRef
    public var serverName: String              // SNI
    public var publicKey: Data                 // 32 bytes
    public var shortID: Data                   // ≤8 bytes
    public var fingerprint: TLSFingerprint     // .chrome (default), .safari26, .firefox148, .random (among MLKEM-capable presets only)
    public var target: WireGuardTarget         // address as reachable from the relay (domain allowed); defaults to the peer endpoint; sent in the VLESS header, never resolved client-side
}
public struct VLESSWebSocketSpec: Codable, Sendable, Hashable {
    public var server: BootstrapAddress; public var uuidRef: SecretRef
    public var host: String; public var path: String /* treated as a secret for redaction */; public var serverName: String
    public var fingerprint: TLSFingerprint; public var earlyData: Int /* 0 = off */; public var target: WireGuardTarget
}
public struct FailoverPolicy: Codable, Sendable, Hashable {
    public var unhealthyWindows: Int           // 2 × 15 s windows of tx-without-rx
    public var recoveryWindow: Duration        // 30 s without failures → healthy
    public var failedEpisodeBackoff: Duration  // 600 s: suppresses automatic *switching*; the current candidate keeps retrying with its own backoff
    public var order: [TransportID]
    public var automaticFailback: Bool         // false
}
```

Carrier transports are restricted to single-peer profiles in v1 (`carrierRequiresSinglePeer`). With a carrier active the effective MTU is 1420 and the effective `PersistentKeepalive` is clamped to ≤ 25 s (`keepaliveClampedByCarrier` shown in the UI).

### 8.2 `SwitchBind` and inner transports
`SwitchBind` is the only `conn.Bind` passed to `device.NewDevice`. `ParseEndpoint` returns a neutral `wgexEndpoint{netip.AddrPort}` valid for every inner transport. `Open` returns immediately with `ReceiveFunc`s that read from internal channels fed by whichever inner transport is active; they block across reconnects and return `net.ErrClosed` only after `Close` (so wireguard-go's receive routines never die from carrier errors). `Send` routes to the active inner transport; while a carrier is reconnecting it drops, counts and returns nil. `BatchSize` is a constant for the device's lifetime (1 on extensions, ≤ 32 on the Mac). Writes to a stream carrier are serialised by a per-stream mutex and carry a 5 s deadline (timeout → close and reconnect). Carrier dialling runs in an owned goroutine started on activation, never inside `Open`. `wgex_set_transport` swaps the inner transport under `SwitchBind`'s own mutex; `BindUpdate` is called only for UDP rebinds. The `udp` inner transport is one unconnected socket per family bound to the underlay interface (no connected sockets in v1).

VLESS framing: request header (`0x00`, 16-byte UUID, addons `0x00`, command `0x02`, port BE, address type `0x01`/`0x02`/`0x03` and address of the target), response header `0x00 0x00` tolerated late, datagrams as 2-byte big-endian length plus payload (drop > 8190 bytes; reject > 65535). Reconnect: jittered exponential backoff 1 s → 60 s, generation-tagged, cancelled by `Close`; bounded queues (256 each way); events `carrierConnected`, `carrierDisconnected(reason)`, `authFailed`, `certificateMismatch`.


### 8.3 Bootstrap and health
Before catch-all routes exist the controller resolves (UnderlayResolver) and verifies the carrier's bootstrap address (handshake success is the proof) through bound sockets; pf `connecting`/`connected` include passes for **every candidate's** bootstrap endpoints from connect time and are recomputed atomically before a switch. Health signals come from engine events (§4.1) plus `carrierConnected`. The optional in-tunnel HTTP probe is off by default and disabled whenever iOS `includeAllNetworks` is on (the provider cannot bind in-tunnel sockets then). Switching is a whole-path commit through the state machine (`reasserting(.transportSwitch)`); NE settings and routes do not change; only the inner transport changes.

## 9. NE provider specifics

- **`ProtocolConfigurationBuilder`** (app side, `WGEXNEClient`) builds the `NETunnelProviderProtocol`: `providerBundleIdentifier = BuildIdentifiers.tunnelExtension`, `passwordReference`, and on **`NEVPNProtocol`** the flags that the 27 SDK exposes only there: iOS `includeAllNetworks`, `excludeLocalNetworks`, `excludeCellularServices`, `excludeAPNs`, `excludeDeviceCommunication` (all set explicitly from `IOSProtection`, never left to defaults), tvOS `enforceRoutes = true`; then `saveToPreferences` and a tunnel restart when a flag changed (Mullvad pattern).
- **`NESettingsGenerator`** (provider side) emits only `NEIPv4Settings`/`NEIPv6Settings` (addresses, included routes from AllowedIPs, no `/120` clamp), `NEDNSSettings` (`allowFailover = false`, `matchDomains` per policy), MTU (1280 default; 1420 cap with a carrier) and `tunnelRemoteAddress = "127.0.0.1"` (constant; the observed endpoint is shown from statistics, and endpoint changes never re-apply settings). v4-only profiles with `.blockOutside` get `NEIPv6Settings(addresses: ["fdf0:7765:7800::1"], networkPrefixLengths: [128])` with included route `::/0` so IPv6 is swallowed by the tunnel. tvOS `allowLAN` adds `excludedRoutes` for `10/8, 172.16/12, 192.168/16, 169.254/16, 224/4, fe80::/10, fc00::/7, ff00::/8` (hardware verification against `enforceRoutes` in P4-14a; if excluded routes lose, `enforceRoutes` defaults to off with on-demand only and the UI says so).
- `NEManagerClient`: Firezone-pattern protocols; load before first save; actor-serialised; skip equivalent writes; reload and retry once after a failed save; never trust a mutated manager after failure. Conforms to `TunnelBackend` (P3-02b).
- On-demand compiler (`WGEXPolicy`): exceptions before fallback, sorted SSIDs, `.any` on tvOS, disconnect rules for excluded SSIDs, `.cellular` only on iOS; on-demand is disarmed before a manual stop and re-armed on the next user start.
- App ↔ provider: `ProviderMessage` (`status`, `statistics`, `subscribeStats(interval)`, `unsubscribeStats`, `reload(profileID)`, `setTransport`, `logs(since)`) and `ProviderReply`, ≤ 256 KiB.

## 10. Profile store and journal (`WGEXProfileStore`)

Files: `<container>/profiles/<uuid>.json`, `<container>/journal.json`, `<container>/settings.json`; app group container on iOS/tvOS/Mac app; `/Library/Application Support/WGEX/profiles/` for the daemon registry (`ProfileRegistry`: owner uid, revision idempotence, `purgeSecrets`). Keychain items: service `BuildIdentifiers.base`, account `<profileID>/<secret-kind>/<id>`. `KeychainSecretStore` is exercised only in hosted, signed test bundles; `swift test` uses `InMemorySecretStore`. Operations are journalled (`stage secret → write profile → install into backend → verify → retire old secret`); startup reconciliation consults the journal first; migrations keep the previous document until read-back succeeds.

Import pipeline: `ImportSource` (`.file(URL, securityScoped)`, `.documentOpen(URL)` for the registered `.conf` document type and Open-In, `.text`, `.zip(URL)` through the bounded reader, `.qrImage(CGImage)`, `.camera(String)`, `.pairing(ProfilePayload)`) → guards → `parseWgQuick` → `ImportReview` (diagnostics, duplicates, `keyInUseElsewhere` warning when the public key matches an installed profile) → user confirms → `importProfile` → optional `installIntoBackend`. QR text that is not a configuration is reported and never opened.

ZIP import permits at most 1,024 entries including ignored files and directories, 256 KiB per configuration entry, and 256 MiB each for compressed input and total advertised expanded data (`Packages/WGEXProfileStore/Sources/WGEXProfileStore/ZipArchiveReader.swift:10`, `Packages/WGEXCore/Sources/WGEXCore/Configuration/ConfigDiagnostic.swift:33`). Stored and deflate entries are supported (`Packages/WGEXProfileStore/Sources/WGEXProfileStore/ZipArchiveReader.swift:18`). On Mac, Export All Tunnels is available in the main window and File menu; it warns about keys before the save panel and writes flat `.conf` entries in a ZIP (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift:296`, `Apps/WGEXMac/WGEXMacApp.swift:37`, `Apps/WGEXMac/WGEXMacApp.swift:268`, `Apps/WGEXMac/MacAppModel+ExportAll.swift:12`, `Apps/WGEXMac/MacTunnelArchive.swift:9`, `Packages/WGEXUI/Sources/WGEXUI/Presentation/MacStrings+Export.swift:29`). The menu-bar Import Tunnels command opens the main window's importer (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift:112`, `Apps/WGEXMac/WGEXMacApp.swift:183`, `Apps/WGEXMac/MacAppModel+Import.swift:17`).

## 11. Pairing (`WGEXPairing`)

Two modes. **QR mode** (iPhone/iPad sender): the QR authenticates the TV's key. **Manual mode** (Mac or no camera): commit-then-reveal with a mutually confirmed short authentication string before anything secret is sent.

```
TV                                                        Sender
 session {sid, X25519 ephemeral pk_TV, expiry 120 s}
 advertise _wgex-pair._tcp TXT{v=1}            (no sid)
 QR: wgex-pair://v1/<sid>/<pk_TV b64url>       (QR mode)
                                                           QR mode: scan; manual mode: pick the TV from the Bonjour list
                                                           connect (NWConnection TCP), hello{sid?, pk_S ephemeral, version}
 manual mode: commit = SHA256(pk_TV ‖ nonce_TV)  → sender; sender replies ack
 manual mode: reveal pk_TV, nonce_TV            → sender verifies the commitment
 both: ctx = HPKE.Sender/Recipient(.Curve25519_SHA256_ChachaPoly, info = "wgex-pair v1" ‖ sid ‖ pk_TV ‖ pk_S)
 both: SAS = decimal(exportSecret(context: "wgex-sas v1" ‖ transcript, 8 bytes))[0..<6]
 both display SAS; manual mode: user confirms on TV AND on sender before sealing; QR mode: TV asks "Accept profile from <sender>? (SAS shown)"
                                                           seal(profile JSON incl. secrets, aad = sid)  ≤ 64 KiB
 open; validate with the standard parser; ask before overwriting; store; ack
 stop advertising; close
```

**Amendment (25 October 2026, pending ratification at the transport security review).** After the HPKE context is set up, the sender acknowledges the encapsulated key and both sides exchange nonce commitments before either displays the SAS, so an attacker cannot grind the SAS offline; the `info` binding and the SAS exporter formula are unchanged. Sealed plaintext is capped at 65 514 bytes so the ciphertext fits the 64 KiB frame.

Attempts are counted after the SAS stage (3 per session); a third device cannot exhaust them without reaching the SAS. No system URL scheme is registered; `wgex-pair://` payloads are accepted only from the in-app scanner. A MITM test harness (substituted `pk_TV`, SAS grinding) must fail in P5-29. The TV's fallback when pairing is impossible (client isolation, LAN blocked by the sender's kill switch) is **paste import** via the Continuity Keyboard (P5-31); the sender checks LAN reachability first and explains blockers ("Allow LAN is off", "Force all traffic is blocking your local network").

## 12. CLI (`wgex`)

Embedded at `WGEX.app/Contents/Helpers/wgex` (identifier `<base>.cli`, embedded Info.plist via `CREATE_INFOPLIST_SECTION_IN_BINARY`). Commands: `status [--json]`, `up <profile>`, `down`, `profiles`, `lockdown on|off`, `captive open [minutes]|close`, `transport <profile> <id|auto>`, `logs [--follow]`, `diagnostics export <path>`, `downgrade --allow`, `doctor`. The CLI never reads the Keychain: `up` succeeds when the daemon holds the profile's secrets (intended-up or start-before-login); otherwise the daemon asks the console user's running app over `provideSecrets`, and if no app is running `up` exits 3 with `secretsUnavailable: open WGEX to connect`. Settings shows an `alias` line instead of creating a symlink under `/usr/local/bin`.

## 13. Live Activity (iOS)

`WGEXLiveActivity.appex` (WidgetKit extension with an `ActivityConfiguration` only; `NSSupportsLiveActivities = YES` in the app's Info.plist; attributes in `WGEXActivityShared`). Content: state, profile name (hidden by default on the Lock Screen; setting), `Text(timerInterval:)` for connected-since and handshake age; **no byte rates**. Every update sets `staleDate = now + 60 s`; the stale presentation shows "Status unknown, open WGEX" with no protection colour. P5-16a spikes whether the provider process can call `Activity.update`/`end` (the SDK does not mark them unavailable to extensions); if it can, the provider drives updates on state edges (≤ 1 per 5 s); otherwise the app updates on foreground and the staleness model covers the rest. The 8-hour system cap: the activity is shown for user-initiated sessions and attention states (connecting, reconnecting, blocked, failed), not permanently for always-on; the app re-requests it on foreground when relevant. A `LiveActivityIntent` "Disconnect" button is included (no App Shortcut, so no Siri or Shortcuts exposure).

## 14. Diagnostics (`WGEXDiagnostics`)

Categories: `app`, `daemon`, `provider`, `engine`, `routes`, `dns`, `pf`, `xpc`, `store`, `pairing`, `transport`, `policy`. Ring buffer per process (4096 lines × 512 bytes; long lines are split with a continuation marker so the redactor sees them whole). The diagnostics bundle format `wgex-diagnostics-<date>.zip` uses stored entries written by `WGEXDiagnostics` without external tools, with redacted ring buffers, system info, profile summaries without keys, pf anchor dump (Mac), route excerpt and DNS configuration read through SCDynamicStore. The Mac app no longer offers diagnostics bundle export (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacSettingsView.swift:98`). Redaction is exact-match first (every secret, UUID, SSID, profile name, endpoint host, WS path and SNI loaded from the store, including 12-character partial matches) and pattern second (base64 and base64url 42–44 chars with or without padding, 64-hex, UUIDs, IPv4/IPv6 literals and CIDR shorthand unless "include endpoints" is ticked). Daemon diagnostics and log subscriptions are filtered per uid (§5).

## 15. Update flow (macOS)

1. Sparkle downloads and verifies (EdDSA + Developer ID), replaces `WGEX.app` atomically (root-owned after secure install; authorised installer), relaunches.
2. New app `hello` → `protocolMismatch` or `versionMismatch`.
3. App sends `prepareForUpdate` (admin right; client build newer); daemon exits cleanly, pf rules and token stay in the kernel.
4. App `try await unregister()` (completion-based; "safe to re-register after the completion handler"), then `register()`, then polls `status` until `.enabled` (10 s timeout → UI state "Needs approval again" with the deep link).
5. Launchd starts the new daemon on the next connection: reconciliation (§4.2) applies the blocking policy first, restarts the engine from the daemon store (intended-up secrets persist), re-verifies routes/DNS/pf. Target: under 3 s of blocked time and zero leaked markers (P7-04).
