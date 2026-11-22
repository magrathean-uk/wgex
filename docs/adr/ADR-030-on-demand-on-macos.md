# ADR-030 On-demand activation on macOS

Status: Accepted (M02-T01; approved by the M02 cross-vendor review, merged as 4eca721). It supersedes the sentence "no SSID rules on the Mac in v1" in [ADR-009](ADR-009-kill-switch-and-protection-semantics.md) and the `macOSUsesDaemon` diagnostic in `Packages/WGEXPolicy/Sources/WGEXPolicy/OnDemandCompiler.swift`. It extends the secret-retention rule of [ADR-008](ADR-008-keys-and-secret-storage.md) and the tunnel-lifetime rules of [ADR-026](ADR-026-tunnel-lifetime-on-macos.md); it changes no pf, route, DNS or boot mechanism.

## Context

- The official WireGuard Mac app ([wireguard-apple](https://github.com/WireGuard/wireguard-apple) 1.0.16, MIT) stores on-demand rules on its `NETunnelProviderManager` (`ActivateOnDemandOption.apply`). macOS evaluates them in the NetworkExtension on-demand machinery, SSID matching included, so the app never needs the SSID to decide. It reads the current SSID only to offer "Add connected" in the editor.
- WGEX on macOS is a root launch daemon with pf, not NetworkExtension ([ADR-003](ADR-003-macos-backend-root-launch-daemon-with-pf-not-networkextensio.md)). Nothing in the system evaluates rules for it. Today the daemon reads no on-demand field, `OnDemandCompiler` returns no macOS rules, the macOS default policy is `.off` (`Packages/WGEXCore/Sources/WGEXCore/Configuration/ProtectionPolicy.swift`), and Mac Settings says there are no SSID rules on macOS (`Packages/WGEXUI/Sources/WGEXUI/Presentation/MacStrings+Settings.swift`).
- The daemon tracks the configd primary interface (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/UnderlayMonitor/SystemUnderlayMonitor.swift`) with a 500 ms trailing, 3 s ceiling debounce (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/DaemonNetworkMonitoring.swift`), but never classifies it as Wi-Fi or Ethernet.
- Fact: the CoreWLAN header states that SSID information is unavailable unless Location Services is enabled and the calling app is authorised; Apple developer forum reports date the enforcement to macOS 14. Location authorisation is granted by a user to an app. Inference, not measured: a launch daemon cannot obtain it on macOS 27, and undocumented root routes (configd AirPort keys, `ipconfig getsummary`, `wdutil`, `system_profiler`) are redacted or need a host setting change.
- Existing daemon facts this ADR builds on: exactly one intent at a time (`TunnelIntent { profileID, ownerUID }` in `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Storage/DaemonJournal.swift`); the boot profile is the registry field `startBeforeLoginOverride` (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ProfileRegistry.swift`), at most one; logout stops a tunnel unless its profile has that override (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+Monitoring.swift`); XPC protocol version 7, exact match (`Packages/WGEXBackendMac/Sources/WGEXDaemonProtocol/Messages/Envelope.swift`).

## Decision

### 1. Where rules are evaluated

The daemon evaluates, always. It owns the tunnel lifecycle, runs while the app is quit (ADR-026) and serialises every mutation in `TunnelController`. The app never connects or disconnects on behalf of a rule; its only on-demand runtime role is relaying the SSID (section 3).

- `OnDemandCompiler` (WGEXPolicy) compiles a profile's policy into ordered `OnDemandRule` values for macOS.
- A new pure `OnDemandEvaluator` (WGEXPolicy) maps rules plus a network context (network class, SSID state) to a decision: `connect`, `disconnect` or `hold`.
- A new daemon component, `OnDemandCoordinator` (WGEXDaemonCore), owns the armed state, collects the network context, runs the evaluator on the triggers in section 5 and drives `TunnelController` start and stop. It adds no pf, route or DNS code.

### 2. macOS rule shape

The policy gains one additive case in WGEXCore. Existing cases and their iOS and tvOS compilation are unchanged; cellular stays iOS-only.

```swift
public enum OnDemandPolicy: Codable, Sendable, Hashable {
    case off
    case always(exceptSSIDs: [String])
    case wifiOnly(exceptSSIDs: [String])
    case cellularOnly                          // iOS only
    case interfaces(OnDemandInterfaces)        // new: the macOS editor writes only .off or this case
}
public enum OnDemandInterfaces: Codable, Sendable, Hashable {
    case ethernetOnly                          // official "Ethernet only"
    case wifiOnly(OnDemandSSIDMatch)           // official "Wi-Fi only"
    case wifiOrEthernet(OnDemandSSIDMatch)     // official "Wi-Fi or ethernet"
}
public enum OnDemandSSIDMatch: Codable, Sendable, Hashable {
    case anySSID
    case onlySSIDs([String])                   // include list
    case exceptSSIDs([String])                 // exclude list
}
```

Network class on macOS: `wifi` when the configd primary interface (the IPv4 primary, else the IPv6 primary) has `SCNetworkInterfaceGetInterfaceType` equal to IEEE 802.11; `ethernet` for every other primary interface (built-in or USB Ethernet, Thunderbolt Bridge, iPhone USB); `none` when there is no primary interface. The WGEX utun is never the classified interface. This matches the official app's mapping of "non-Wi-Fi" to Ethernet on macOS.

`OnDemandRule.Interface` keeps `any`, `wifi` and `cellular`; no case is added, so `Packages/WGEXBackendNE/Sources/WGEXNEClient/ProtocolConfigurationBuilder.swift` is untouched. Ethernet is expressed as an `any` rule placed after every Wi-Fi rule. SSID lists are de-duplicated and sorted, as today. Compiled macOS rules (first match wins; S is the SSID list):

| Policy | Rules in order | Official 1.0.16 option |
|---|---|---|
| `ethernetOnly` | disconnect wifi; connect any | `nonWiFiInterfaceOnly` |
| `wifiOnly(anySSID)` | connect wifi; disconnect any | `wiFiInterfaceOnly(anySSID)` |
| `wifiOnly(onlySSIDs S)` | connect wifi in S; disconnect any | `wiFiInterfaceOnly(onlySpecificSSIDs)` |
| `wifiOnly(exceptSSIDs S)` | disconnect wifi in S; connect wifi; disconnect any | `wiFiInterfaceOnly(exceptSpecificSSIDs)` |
| `wifiOrEthernet(anySSID)` | connect any | `anyInterface(anySSID)` |
| `wifiOrEthernet(onlySSIDs S)` | connect wifi in S; disconnect wifi; connect any | `anyInterface(onlySpecificSSIDs)` |
| `wifiOrEthernet(exceptSSIDs S)` | disconnect wifi in S; connect any | `anyInterface(exceptSpecificSSIDs)` |

Each row gives the same outcome as the official rule list on every Wi-Fi and Ethernet network. On macOS the legacy cases normalise first: `.always(exceptSSIDs:)` becomes `wifiOrEthernet` (empty list `anySSID`, else `exceptSSIDs`), `.wifiOnly(exceptSSIDs:)` becomes `wifiOnly` likewise, `.cellularOnly` keeps `cellularRequiresIOS` with no rules. On iOS and tvOS `.interfaces` emits no rules and a new diagnostic `interfacesRequiresMacOS`. `macOSUsesDaemon` is deleted.

Validation (`Packages/WGEXCore/Sources/WGEXCore/Configuration/ProfileValidation.swift`): an `onlySSIDs` or `exceptSSIDs` list holds 1 to 64 entries; each SSID is 1 to 32 bytes of UTF-8 with no control characters; duplicates are an error; every SSID joins the public-field key check, as the existing lists do. An empty list is written as `anySSID` by the editor.

Evaluation (`OnDemandEvaluator`): a rule matches when its interface matches the network class (`any` matches `wifi` and `ethernet`) and, when it carries a list, the SSID is in the list by exact string equality (SSIDs are case-sensitive). On `wifi` with the SSID unknown (section 4), a disconnect rule with a list does not match, and reaching a connect rule with a list ends evaluation with `hold`. Every macOS list ends in an `any` rule, so a satisfied network always yields `connect`, `disconnect` or `hold`; class `none` yields `hold`.

### 3. Reading the SSID on macOS 27

The app reads the SSID and relays it to the daemon. The daemon never reads the SSID, never asks configd, `ipconfig`, `wdutil` or `system_profiler` for it, and changes no host setting to unredact it.

- The Mac app gains the hardened-runtime location entitlement `com.apple.security.personal-information.location` (`Apps/WGEXMac/WGEXMac.entitlements`) and `NSLocationUsageDescription` (`Apps/WGEXMac/Info.plist`).
- It requests Location authorisation through `CLLocationManager` only when the user saves or arms a profile whose policy holds an SSID list, or asks for "Add connected"; never at launch or for SSID-free policies.
- It reads the SSID with CoreWLAN (`CWWiFiClient`, `ssid()` on the named interface) and watches SSID and link changes through CoreWLAN event monitoring.
- An eligible reporter is a daemon connection with the app's signing identifier (not the CLI), from the console user, with an active event subscription.
- The app reports with `reportWiFiNetwork` (section 8) on every `wifiNetworkRequested` event, whatever it knows of the armed state, so a request can never race the reply to `armOnDemand`. While a profile it owns is armed with an SSID list it also reports when its event subscription starts, on every CoreWLAN SSID or link change, and on every Location-authorisation change (`locationManagerDidChangeAuthorization`): a revoked, restricted or denied authorisation reports `notAuthorised`, a granted one reports a fresh reading.
- The daemon accepts a report only from an eligible reporter, naming the current Wi-Fi primary interface, with `observedAtContinuous` (the clock of `TunnelStatus.measuredAtContinuous`) no earlier than the daemon's last invalidation of the SSID. It ignores any other report. It holds the accepted SSID in memory only.
- The daemon invalidates the held SSID on: every underlay change while the class is `wifi`; a change of primary interface; wake; daemon start; arming a profile whose policy holds an SSID list; an install that gives the armed profile an SSID-list policy or changes its list; a change of console user; and the loss of an eligible reporter (its connection is invalidated or interrupted, or it ends its event subscription). After an invalidation, while the armed policy holds an SSID list, it sends `wifiNetworkRequested` to every eligible reporter; with none left the SSID is unknown with reason `noReporter`. Arming an SSID-list policy on an unchanged Wi-Fi network therefore always asks for a fresh reading instead of waiting for a network change.

### 4. Without SSID access

The SSID is unknown when no eligible reporter is connected, Location is denied or not yet granted, the report is stale, or the reading is anything other than `ssid` (unreadable because redacted or not UTF-8, or not associated).

- SSID-free policies (`ethernetOnly`, `wifiOnly(anySSID)`, `wifiOrEthernet(anySSID)`) never need the SSID and work fully without the app.
- An exclude list skips its disconnect rule, so the tunnel connects: a trusted network that cannot be confirmed is treated as untrusted.
- An include list ends in `hold`: the profile keeps its current state, so no tunnel is torn down or raised on a guess.
- Settling applies only when the armed policy holds an SSID list and the class is `wifi`. After an invalidation, while an eligible reporter is connected, the coordinator holds for up to 3 s for a fresh report before evaluating with the SSID unknown; with none it evaluates at once. At daemon start it holds for up to 10 s while the owner is the console user, whether or not an app has subscribed yet, so a restarting app can report first.
- Losing the last eligible reporter makes the SSID unknown at once and the coordinator evaluates without settling, so the unknown-SSID decisions above apply: under an exclude list, quitting the app on a trusted network raises the tunnel; under an include list the tunnel keeps its state. A remaining reporter is asked for a fresh reading and settles as above.
- The status reports why (section 8), and the Mac app tells the user to open WGEX or allow Location. The documented known gap stays: a hostile network can imitate a trusted SSID ([protection semantics](../protection-semantics.md)); no BSSID binding, as in the official app.

### 5. Arming and evaluation triggers

A profile with a policy other than `.off` is armed or disarmed; armed is the official "On-Demand Enabled". At most one profile is armed; arming one disarms the other (stopping it if intended, as below). Arming is refused while a cutover is armed, as enabling Lockdown is.

Evaluation runs for the armed profile on: arming; an install that changes its policy; each debounced underlay change; an accepted SSID report, including one sent on a Location-authorisation change; the loss of an eligible reporter; wake; console-user change; the end of another profile's intent; the end of recovery; daemon start after reconciliation. A trigger that also invalidates the SSID (section 3) evaluates after settling (section 4). Requests arriving while a controller operation is in flight are coalesced and re-run when it finishes (latest wins).

Evaluation is active while the profile owner is the console user, or at any time when the profile also has `startBeforeLoginOverride`. Otherwise it is paused: the existing logout and console-switch rule stops a tunnel without the override, and the armed state persists. When the owner becomes the console user again the coordinator clears that profile's `loginSuspended` mark and evaluates. Evaluation is also paused during recovery and while a cutover is armed.

Decisions act only through the existing controller:

| Decision | Armed profile not intended | Armed profile intended |
|---|---|---|
| `connect` | start, intent origin `onDemand`, secrets from the daemon store | no change |
| `disconnect` | no change | stop with the new `StopReason.onDemand` |
| `hold` | no change | no change |

`connect` while another profile holds the intent becomes `hold` (reason `anotherTunnelActive`). `StopReason.onDemand` clears the intent, sets no `loginSuspended` mark and keeps the secrets. A failed on-demand start behaves as a manual one: the intent stays, pf blocks in `connecting` and `error`, and the existing maintenance retry runs; the coordinator never retries or stops on failure.

### 6. Manual connect and disconnect

Manual action always wins and stays in force until the user arms again. The official rules are kept where they exist:

1. The Mac app's window toggle and menu bar item, for a profile with a policy, arm and disarm (official "Enable On-Demand", "Disable On-Demand", "Disable On-Demand and Deactivate").
2. `disarmOnDemand` stops the profile if it is intended, whatever started it.
3. A manual disconnect (`stop` or `stopCurrent` with `userRequested`) of the armed profile disarms it first, then follows the existing explicit-stop path.
4. A manual connect (`startIntent`) of the armed profile disarms it and connects with origin `manual`; the CLI `up` reaches this (WGEX addition: the official app has no force-connect for a profile with rules).
5. Connecting another profile while one is armed disarms the armed one. If the armed one is intended, `controllerAnotherTunnelActive` still applies; the client's switch sequence stops it first (rule 3), which matches the official app's "disable on-demand, deactivate, then activate".
6. Arming while another profile is manually intended leaves that tunnel alone; the armed profile holds until it stops.
7. An install that sets the policy to `.off` clears the armed flag and leaves the tunnel as it is (official `apply`). Saving a policy that introduces rules on an intended profile is followed by the app arming it (official `modify` with `shouldEnsureOnDemandEnabled`); the daemon never arms on install.
8. Removing a profile or uninstalling disarms it.

### 7. Lockdown, kill switch, boot intent, captive window

- **Lockdown wins.** On-demand never changes `MacGlobalSettings.lockdown`. A `disconnect` decision with Lockdown on leaves pf in `lockdown` and protection `blocked`, as a manual disconnect does today. The Mac editor warns that networks where on-demand disconnects have no connectivity while Lockdown is on.
- **Kill switch unchanged.** An on-demand start sets an intent exactly as `startIntent` does, so the always-on blocking in `connecting`, `reasserting` and `error` applies unchanged. A `disconnect` decision with Lockdown off moves pf to `disconnected` and protection to `unprotected`. No pf policy, anchor rule or pass is added.
- **Boot intent.** `startBeforeLoginOverride` keeps its meaning and its uniqueness. For an armed profile it only decides whether evaluation runs without the owner's console session (before login, after logout, under another user) and whether the tunnel survives logout. Reconciliation (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+Reconciliation.swift`) skips its boot reservation for an armed profile and lets the coordinator decide; restoration of a journalled intent is otherwise unchanged. The coordinator never starts an armed profile without the override before the owner logs in; an intent restored after a power loss is handled as today and evaluated once the owner logs in.
- **Captive window.** On-demand never opens, extends or closes a window by itself. While a window is open a `connect` decision is a no-op; a `disconnect` decision stops the profile and the stop withdraws the window as a user disconnect does (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+Captive.swift`).
- **Secrets.** Armed is a third retention reason beside intended-up and start-before-login: arming stores the profile's secrets in the daemon store; an on-demand stop keeps them; disarming deletes them unless another reason holds; a manual disconnect follows the existing explicit-stop rule after disarming.

### 8. New XPC messages, status and persisted fields

Protocol version 7 becomes 8 (exact match unchanged). Message definitions live in `Packages/WGEXBackendMac/Sources/WGEXDaemonProtocol/Messages/Request.swift` and `Packages/WGEXBackendMac/Sources/WGEXDaemonProtocol/Messages/Event.swift`; rows in `Packages/WGEXBackendMac/Sources/WGEXDaemonProtocol/Authorisation/AuthorisationTable.swift`.

| Message | Carried by | Authorisation | Recovery |
|---|---|---|---|
| `Request.armOnDemand(profileID: UUID, hasSecrets: Bool)` | new `@objc` method `armOnDemand(_ envelope: Data, secrets: Data, reply:)` on `WGEXDaemonXPC` | owner and console user, or root (as `startIntent`) | refused |
| `Request.disarmOnDemand(profileID: UUID)` | `send` | owner (as `stop`) | allowed |
| `Request.reportWiFiNetwork(WiFiObservation)` | `send` | new policy `consoleUserApp`: console user and the app's signing identifier | refused |
| `Event.wifiNetworkRequested(interfaceName: String)` | client events interface | sent to eligible reporters only (section 3) | not sent |

- `RequestKind` gains `armOnDemand`, `disarmOnDemand` and `reportWiFiNetwork`; the profile requests map to their profile in the dispatcher's owner lookup. `armOnDemand` joins the secrets allowlist; with `hasSecrets` false (the CLI) it follows the CLI `up` path through `provideSecrets`.
- Replies are `.ok` or `.error`; there is no new `Reply` case. Arming a profile whose policy is `.off` or does not compile fails with a new error value `onDemandNotConfigured`.
- `WiFiObservation { interfaceName: String, reading: WiFiReading, observedAtContinuous: TimeInterval }` with `WiFiReading` `ssid(String)`, `notAuthorised`, `unreadable`, `notAssociated` (WGEXDaemonProtocol).
- `TunnelStatus.onDemand: OnDemandStatus?` (WGEXCore, `Packages/WGEXCore/Sources/WGEXCore/Status/TunnelStatus.swift`; nil from backends without on-demand): `armedProfileID: UUID?`, `activated: Bool` (the current intent was started by on-demand), `network` (`none`, `ethernet`, `wifi`), `ssid` (`notRequired`, `known`, `settling`, `unavailable(reason)` with `noReporter`, `notAuthorised`, `timedOut`, `unreadable`), `decision` (`connect`, `disconnect`, `hold(reason)` with `noNetwork`, `ssidUnavailable`, `anotherTunnelActive`, or `paused(reason)` with `ownerNotConsoleUser`, `recovering`, `cutoverArmed`), `evaluatedAtContinuous: TimeInterval?`. Status never carries an SSID.
- `StopReason.onDemand` (`Packages/WGEXCore/Sources/WGEXCore/Status/StopReason.swift`). `DaemonClient` adds `.onDemand` to its capabilities (`Packages/WGEXBackendMac/Sources/WGEXDaemonClient/DaemonClient.swift`).
- CLI (`Packages/WGEXBackendMac/Sources/WGEXDaemonClient/WGEXCLICore.swift`): `wgex on-demand <UUID> on` and `wgex on-demand <UUID> off`; `wgex status --json` gains an `onDemand` object with the status fields.

Persisted fields:

| Field | Where | Notes |
|---|---|---|
| `TunnelProfile.onDemand` holding `.interfaces(...)` | daemon registry profile document and the app's profile store | additive Codable case; profile schema version stays 1 |
| `OnDemandRecord` | registry, the `on-demand.state` file in the profiles directory | armed selection and owed releases in one record; see the structural addendum |
| `TunnelIntent.origin: IntentOrigin?` with `manual`, `onDemand` | journal, `DaemonJournal.swift` | nil reads as `manual`; drives `activated` after a restart |
| armed as a secret-retention reason | daemon secret store | no new file |

Not persisted: SSID observations, the last decision, the network class. They are rebuilt after every restart.

### 9. Parity with the official WireGuard Mac app

Matched: the option set (Off, Ethernet only, Wi-Fi only, Wi-Fi or Ethernet; Any SSID, Only these SSIDs, Except these SSIDs) and the compiled outcome per network (section 2); arming as the primary control and disarm-with-deactivate (section 6, rules 1 to 3); activating another tunnel disables on-demand on the running one (rule 5); introducing rules on an active tunnel arms it (rule 7); one active tunnel at a time; status shows armed and active separately.

Differs, by design: rules are evaluated by the WGEX daemon, not NetworkExtension; the SSID comes from the app under Location authorisation, with the section 4 behaviour when it is missing; a manual connect overrides and disarms (rule 4); before-login evaluation exists only for profiles with start-before-login, an existing WGEX feature; Lockdown, which the official app lacks, takes precedence. Nothing here goes deeper than the official app at kernel, pf or boot level: no kernel component, no new pf rule or anchor, no launchd or early-boot change.

## Addendum: structural coordination built in M02-T02

This addendum supersedes the earlier persisted armed-flag description and DEC-008's control lane. Source references below are repository paths and line numbers.

- **Admission and commits.** Each control entry point takes a non-copyable `Admission` before its first await; derived commands carry their parent's receipt. Command kind determines supersession and holds, including stops fencing older starts and arms. Admission and compare-and-set commit are synchronous locked sections, with no control lane held across an await. A commit checks liveness and newer fences and watermarks before writing, so affected commits follow receipt order (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:60`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:79`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:277`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:321`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:427`).
- **Manual hold.** During a manual command, its admission holds the relevant profile against on-demand actions; a manual connect also holds the armed profile. A manual connect disarms the selection and a manual disconnect disarms its armed profile before stopping. The selection remains disarmed until armed again, as in section 6 (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:22`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:147`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/Admission.swift:397`; `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemandControl.swift:152`; `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ProfileRegistry+OnDemandCommits.swift:63`).
- **Evaluation.** Each input advances an evaluation epoch, invalidating earlier decisions. Inputs applied across awaits hold evaluation until applied; a decision ticket must still match the epoch and current operation before acting (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:53`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:60`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:248`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:355`).
- **Durable selection.** the `on-demand.state` file in the profiles directory replaces the proposed per-profile armed flag and the intermediate `on-demand.switch`: one atomic replacement records the armed selection and all owed releases. A newer intent claim discharges an owed stop, while retention is checked when the release completes (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ArmedSelection.swift:6`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ArmedSelection.swift:20`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ArmedSelection.swift:43`; `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/DirectoryProfileRepository.swift:89`; `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Storage/StateDirectory.swift:132`).
- **Purge and secrets.** Purge commits a tombstone and registration removal first, then deletes secrets idempotently; reuse waits for any outstanding purge. Bundle publication and retention-dependent deletion are ordered per profile, with retention checked inside the ordered write (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ProfileRegistry.swift:354`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ProfileRegistry.swift:384`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ProfileRegistry.swift:417`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Registry/ProfileRegistry.swift:467`; `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemandControl.swift:111`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemandControl.swift:287`).
- **Recovery.** Recovery entry invalidates SSID knowledge. At recovery end the coordinator invalidates it again and, when an armed policy needs an SSID on Wi-Fi, asks eligible app reporters for a fresh reading (`Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+Reconciliation.swift:13`; `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:73`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:126`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:145`, `Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/TunnelController+OnDemand.swift:160`).

## Consequences

- Implementation touches WGEXCore (`OnDemandPolicy`, `ProfileValidation`, `StopReason`, `TunnelStatus`), WGEXPolicy, WGEXBackendMac and the CLI (M02-T02), and the Mac app, WGEXUI and app composition (M02-T04). Adding a case to `OnDemandPolicy` breaks the exhaustive switches in the iOS screens of WGEXUI, which need a matching arm in the same change.
- A build older than this one cannot decode a profile that uses `.interfaces`; the explicit downgrade path must say so.
- The Mac editor replaces the "No trusted Wi-Fi or SSID rules on macOS" copy and gains the official editor shape: Ethernet and Wi-Fi checkboxes, the SSID option and list, "Add connected".
- Tests: WGEXPolicy table tests for every row of section 2, legacy normalisation and the iOS and tvOS outputs; an evaluator matrix over class, SSID state and policy; daemon tests with a fake underlay, fake reports and a fake controller covering arming, every section 6 rule, sections 4 and 7, report freshness, the authorisation rows and the recovery allowlist, restart persistence and the protocol version. Daemon tests also cover each SSID transition of section 3: arming an include policy on an unchanged Wi-Fi network with a subscribed reporter and no network event (the daemon invalidates and sends `wifiNetworkRequested`; a fresh listed SSID connects, no report settles after 3 s to `hold(ssidUnavailable)` with SSID state `unavailable(timedOut)`); an install that adds or changes the armed profile's list; losing the last eligible reporter after an exclude-list `disconnect` (the SSID becomes `noReporter` and the tunnel starts at once); losing one of two reporters (request and settle); and a Location-authorisation change each way (a `notAuthorised` report under an exclude list starts the tunnel; a later `ssid` report of a listed network stops it). App tests with a fake location manager and a fake CoreWLAN client check that each authorisation change and each `wifiNetworkRequested` sends a report. Existing lockdown and kill-switch tests stay green unchanged.
- Lab: a Tart guest has a virtual Ethernet interface and no Wi-Fi, so lab rows cover Ethernet only (arm, disarm, restart persistence, Lockdown with a `disconnect` decision). The SSID relay, Location prompt and Wi-Fi rows are verified at the maintainer's sitting on real macOS 27 hardware.

## Rejected

- Evaluating in the app: rules would stop with the app, contrary to ADR-026.
- The daemon reading the SSID: blocked by the Location gate; the remaining root routes are undocumented, redacted or need a host setting change.
- A NetworkExtension provider only for on-demand: ADR-003 rejects the hybrid daemon plus system extension.
- Treating an unknown SSID as matching every list, or as matching none for both actions: the first disconnects on a guess under exclude lists, the second raises tunnels on unlisted networks under include lists.
- Binding trusted networks to BSSIDs: beyond the official app, and gated by Location as well.
