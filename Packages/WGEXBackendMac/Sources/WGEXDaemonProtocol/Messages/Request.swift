// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Requests from the app or CLI to the daemon (02 §5).
public enum Request: Codable, Sendable, Hashable {
    /// Version handshake; secrets are sent only after a successful hello.
    case hello(clientVersion: String, clientBuild: Int)
    /// Idempotent by (id, revision); the owner uid comes from the connection.
    case installProfile(DaemonProfile)
    /// Daemon-owned revision CAS; nil expects a new profile. Identical content is idempotent.
    case installProfileCAS(TunnelProfile, expectedRevision: UInt64?)
    /// Reads the current revision for an owner, including nil when the profile is new.
    case profileRevision(UUID)
    /// Fixed reasons qualifying the current protection claim.
    case protectionReasons
    /// Removes a profile.
    case removeProfile(UUID, purgeSecrets: Bool)
    /// Carried by the `start` method with the secrets argument.
    case startIntent(profileID: UUID, transport: TransportID?, hasSecrets: Bool)
    /// Starts a trial connection with a bounded awake-time rollback deadline; secrets use the start method.
    case startCutover(profileID: UUID, confirmWithin: Int, hasSecrets: Bool)
    /// Commits the armed trial, retaining normal tunnel intent.
    case confirmCutover
    /// Reverts the trial and clears its persistent intent and secrets.
    case abortCutover
    /// Stops a profile.
    case stop(profileID: UUID, reason: StopReason)
    /// Stops the active profile, resolved and ownership-checked by the dispatcher.
    case stopCurrent(reason: StopReason)
    /// Selects a transport; nil means automatic.
    case selectTransport(profileID: UUID, transport: TransportID?)
    /// Replaces the global Mac settings.
    case setGlobalSettings(MacGlobalSettings)
    /// Opens the captive window.
    case openCaptiveWindow(seconds: Int)
    /// Extends the captive window.
    case extendCaptiveWindow(seconds: Int)
    /// Subscribes to events; logs are opt-in and uid-filtered.
    case subscribeEvents(includeLogs: Bool)
    /// Closes the captive window.
    case closeCaptiveWindow
    /// Carried by the `setStartBeforeLogin` method when enabling.
    case setStartBeforeLoginIntent(profileID: UUID, enabled: Bool)
    /// Bundle integrity and ownership, readable by any verified client.
    case secureInstallStatus
    /// Root ownership and removal of group/world write; envelope carries the admin right.
    case performSecureInstall
    /// Status snapshot.
    case status
    /// Status with the Lab telemetry fixed in ARCHITECTURE.md (M03-T01): the journal policy and, in Lab builds, the owner pf reference.
    case statusTelemetry
    /// Statistics sample.
    case statistics
    /// Redacted log lines.
    case logs(since: Date?, limit: Int)
    /// Diagnostics bundle.
    case diagnostics(DiagnosticsRequest)
    /// Exits after the reply; only from a newer client build.
    case prepareForUpdate
    /// Removes the daemon's state.
    case uninstall(purgeState: Bool)
    /// Arms on-demand for a profile (ADR-030); carried by the `armOnDemand` method with the secrets argument.
    case armOnDemand(profileID: UUID, hasSecrets: Bool)
    /// Disarms on-demand, stopping the profile if it is intended.
    case disarmOnDemand(profileID: UUID)
    /// The app's Wi-Fi reading for the daemon's on-demand evaluation; never logged, held in memory only.
    case reportWiFiNetwork(WiFiObservation)

    /// The request's row in the authorisation table.
    public var kind: RequestKind {
        switch self {
        case .hello: .hello
        case .installProfile: .installProfile
        case .installProfileCAS, .profileRevision: .installProfile
        case .removeProfile: .removeProfile
        case .startIntent: .startIntent
        case .startCutover: .startCutover
        case .confirmCutover: .confirmCutover
        case .abortCutover: .abortCutover
        case .stop: .stop
        case .stopCurrent: .stopCurrent
        case .selectTransport: .selectTransport
        case .setGlobalSettings: .setGlobalSettings
        case .openCaptiveWindow: .openCaptiveWindow
        case .extendCaptiveWindow: .extendCaptiveWindow
        case .subscribeEvents: .subscribeEvents
        case .closeCaptiveWindow: .closeCaptiveWindow
        case .setStartBeforeLoginIntent: .setStartBeforeLoginIntent
        case .secureInstallStatus: .secureInstallStatus
        case .performSecureInstall: .performSecureInstall
        case .status: .status
        case .statusTelemetry: .status
        case .protectionReasons: .status
        case .statistics: .statistics
        case .logs: .logs
        case .diagnostics: .diagnostics
        case .prepareForUpdate: .prepareForUpdate
        case .uninstall: .uninstall
        case .armOnDemand: .armOnDemand
        case .disarmOnDemand: .disarmOnDemand
        case .reportWiFiNetwork: .reportWiFiNetwork
        }
    }
}
