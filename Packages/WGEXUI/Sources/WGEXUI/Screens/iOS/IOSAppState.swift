// SPDX-License-Identifier: MIT

#if os(iOS)
    import Foundation
    import Observation
    import SwiftUI
    import WGEXCore

    /// The shell's UI seam; storage and backend ownership remain in the application.
    @MainActor
    public protocol IOSAppState: AnyObject, Observable {
        var profiles: [TunnelProfile] { get }
        var selectedProfileID: UUID? { get set }
        var status: TunnelStatus { get }
        var featureFlags: FeatureFlags { get set }
        var protection: ProtectionPolicy { get set }
        var automaticFailover: Bool { get set }
        var notifications: Bool { get set }
        var onboardingComplete: Bool { get set }
        var backendMessage: String { get }
        var operationMessage: String? { get }
        var isBusy: Bool { get }
        var userInitiated: Bool { get }
        var review: ImportReviewModel? { get }
        var importDiagnostics: [ConfigDiagnostic] { get }
        /// Reviews still waiting, the current one included; an archive queues one review per configuration.
        var pendingReviewCount: Int { get }
        /// Every review still waiting, the current one first; a zip import shows them as one ticked list.
        var pendingReviews: [ImportReviewModel] { get }
        var editor: ProfileEditorModel? { get }
        /// The profile the system reports running or starting, whoever started it (app, Settings > VPN, on-demand).
        var activeProfileID: UUID? { get }
        /// The active profile while a saved edit is being applied to its running tunnel, until the tunnel is back.
        var applyingProfileID: UUID? { get }
        /// The active tunnel's latest live sample while a detail watches it; nil otherwise.
        var statistics: TunnelStatistics? { get }
        /// The tunnel `statistics` was read from; a detail shows a sample only for its own tunnel.
        var statisticsProfileID: UUID? { get }
        /// Reads the current Wi-Fi SSID for the on-demand editor; nil where no VPN configuration can be installed.
        var connectedNetwork: (() async -> ConnectedNetworkReading)? { get }
        /// Merged app and extension lines, with UTC timestamps, while View Log is open.
        var logText: String { get }
        func watchLog() async
        /// A fresh UTF-8 snapshot with the shared log's export header.
        func exportLog() -> Data
        /// Writes a temporary ZIP only for an explicit export action. The share sheet removes it on dismissal.
        func exportArchive() async throws -> URL
        /// The pinned wireguard-go revision used by the bundled provider.
        var engineVersion: String { get }
        func toggleConnection() async
        /// Turns one tunnel on or off; turning one on stops any other first (one VPN at a time on iOS).
        func setTunnel(_ id: UUID, on: Bool) async
        /// Samples the active tunnel about once a second until the caller's task is cancelled; nothing polls otherwise.
        func watchStatistics() async
        func deleteProfile(_ id: UUID) async
        func prepareImport(_ text: String)
        func prepareScannedCode(_ payload: String)
        func reportScanFailure(_ failure: IOSScanFailure)
        func importFile(at url: URL)
        func createFromScratch()
        func skipReview()
        func cancelImport()
        func confirmImport() async
        func importReviewed(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets, connect: Bool) throws
        func deleteProfiles(at offsets: IndexSet) async
        func moveProfiles(from offsets: IndexSet, to destination: Int)
        func openEditor(_ profile: TunnelProfile) async
        func saveEditor(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets) throws
        func closeEditor()
        func savePreferences() async
    }

    public extension IOSAppState {
        /// The switch state: on while the tunnel is up or on its way up.
        func isTunnelOn(_ id: UUID) -> Bool {
            guard activeProfileID == id else { return false }
            switch status.phase {
            case .idle, .failed, .stopping: return false
            default: return true
            }
        }

        var allowsProfileSelection: Bool {
            switch status.phase { case .idle, .failed: true; default: false }
        }

        var selectedProfile: TunnelProfile? {
            profiles.first { $0.id == selectedProfileID }
        }

        var statusPresentation: IOSStatusPresentation {
            IOSStatusPresentation(status: status, userInitiated: userInitiated)
        }

        var presentation: ProtectionPresentation {
            statusPresentation.protection
        }
    }
#endif
