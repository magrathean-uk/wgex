// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import NetworkExtension
import WGEXCore
import WGEXNEClient
import WGEXProfileStore
import WGEXUI

/// A backend whose manager arms on-demand from a profile's saved rules without starting or stopping its tunnel (M06-T06).
internal nonisolated protocol OnDemandActivation: Sendable {
    func followOnDemandRules(_ id: UUID) async throws(TunnelError)
}

extension NEManagerClient: OnDemandActivation {}

/// Shell-only metadata, separate from the source-compatible SettingsDocument envelope.
internal struct ShellPreferences: Codable, Hashable {
    internal var onboardingComplete = false
    internal var profileOrder: [UUID] = []
    internal var protection = ProtectionPolicy(ipv6Policy: .tunnel)
    /// The app-wide on-demand policy of earlier versions. It stays here, pending, until it has been moved onto the profile
    /// it was applied to and that profile's installation succeeded (M06-T06); on-demand is per tunnel now.
    internal var legacyOnDemand: OnDemandPolicy?
    /// The profile the pending policy moves onto: the one selected when the earlier file was first read.
    internal var legacyOnDemandProfileID: UUID?
    /// Profiles whose saved policy has not yet been confirmed as armed or disarmed in their manager.
    internal var onDemandActivation: [UUID]?
    internal var automaticFailover = true

    private enum CodingKeys: String, CodingKey {
        case onboardingComplete, profileOrder, protection, automaticFailover
        case legacyOnDemand = "onDemand"
        case legacyOnDemandProfileID = "onDemandProfile"
        case onDemandActivation
    }
}

internal extension AppModel {
    /// Moves the app-wide on-demand policy of an earlier `ios-shell.json` onto the profile it was applied to (`target`,
    /// the one the old app saved it into). It stays pending in the preferences until that profile is stored with it and
    /// installed, so a failed save or install is reported and retried on the next launch; a profile that is gone ends it.
    func migrateOnDemand(_ legacy: OnDemandPolicy, to target: UUID?) async {
        pendingLegacyOnDemand = legacy
        pendingLegacyProfileID = target
        guard let index = profiles.firstIndex(where: { $0.id == target }) else {
            clearLegacyOnDemand()
            do { try writeShellPreferences() }
            catch { operationMessage = Self.migrationFailedMessage }
            return
        }
        do {
            var profile = profiles[index]
            if profile.onDemand != legacy {
                profile.onDemand = legacy
                try await store.save(profile)
                replaceProfile(profile)
            }
            try await installProfile(profile)
            clearLegacyOnDemand()
            try writeShellPreferences()
        } catch {
            // Records the target for the retry when the file can be written; the policy stays pending either way.
            try? writeShellPreferences()
            operationMessage = Self.migrationFailedMessage
        }
    }

    static let migrationFailedMessage = "Settings could not be migrated. They are kept for the next launch."

    func writeShellPreferences() throws {
        let shellData = try JSONEncoder().encode(preferenceSnapshot)
        try shellData.write(to: container.appendingPathComponent("ios-shell.json"), options: .atomic)
    }

    static func applyMessage(for error: any Error) -> String {
        switch error {
        case let error as TunnelError where error == NEManagerClient.reconnectFailure:
            reconnectFailedMessage
        case TunnelError.cancelled, is CancellationError:
            applyInterruptedMessage
        case TunnelError.timedOut:
            applyUnconfirmedMessage
        default:
            editSaveFailedMessage
        }
    }

    static let reconnectFailedMessage = "The edited tunnel could not reconnect. Retry."
    static let applyInterruptedMessage = "Applying changes was interrupted. Check the tunnel status and retry."
    static let applyUnconfirmedMessage = "Applying changes could not be confirmed. Check the tunnel status and retry."
    static let editSaveFailedMessage = "Profile edits could not be saved. Reopen the editor to try again."

    static let onDemandFailedMessage = "On-demand could not be updated for this tunnel. Save it again to retry."

    func storedProfile(_ id: UUID) async throws -> TunnelProfile? {
        do { return try await store.load(id) }
        catch ProfileStoreError.notFound { return nil }
    }

    /// The callback snapshots submitted keys into a new editor, so its baseline cannot establish that stored keys match.
    static func keysMatch(_ submitted: borrowing ParsedSecrets, stored: borrowing ParsedSecrets) throws -> Bool {
        guard submitted.references.keys == stored.references.keys else { return false }
        for reference in submitted.references.keys {
            var before = try SecretBytes(zeroedCount: 32), after = try SecretBytes(zeroedCount: 32)
            try stored.withKey(reference) { key in before.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
            try submitted.withKey(reference) { key in after.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
            guard before.constantTimeEquals(after) else { return false }
        }
        return true
    }

    /// True when only on-demand options, the edit timestamp or retained import text may differ. An unchanged retry also
    /// keeps the keys, so retrying manager activation does not reload the running tunnel.
    static func differsOnlyInOnDemand(_ profile: TunnelProfile, from previous: TunnelProfile) -> Bool {
        var comparable = profile
        comparable.onDemand = previous.onDemand
        comparable.updatedAt = previous.updatedAt
        comparable.original = previous.original
        return comparable == previous
    }

    /// The document is saved, then installed, as the shared commit orders them; a failed install restores the previous
    /// document and installation. No key item is written or retired.
    func saveKeepingKeys(_ profile: TunnelProfile, previous: TunnelProfile) async throws -> TunnelProfile {
        try await store.save(profile)
        do { try await installProfile(profile) }
        catch {
            try? await store.save(previous)
            try? await installProfile(previous)
            throw error
        }
        return profile
    }

    /// Records activation before asking the manager, so a failure or interrupted launch is retried. The user's own choice
    /// replaces any app-wide policy still waiting to move onto this tunnel. Only confirmed activation clears the intent.
    func settleOnDemandEdit(_ id: UUID) async -> Bool {
        pendingOnDemandActivation.insert(id)
        if pendingLegacyProfileID == id {
            clearLegacyOnDemand()
        }
        do { try writeShellPreferences() }
        catch { return false }
        guard await followOnDemandRules(id) else { return false }
        pendingOnDemandActivation.remove(id)
        do { try writeShellPreferences() }
        catch {
            pendingOnDemandActivation.insert(id)
            return false
        }
        return true
    }

    /// Only unfinished activation is retried at launch; a manager the user switched off remains off otherwise.
    func retryOnDemandActivations() async {
        for id in pendingOnDemandActivation.sorted(by: { $0.uuidString < $1.uuidString }) {
            guard let profile = profiles.first(where: { $0.id == id }) else {
                pendingOnDemandActivation.remove(id)
                do { try writeShellPreferences() }
                catch { operationMessage = Self.onDemandFailedMessage }
                continue
            }
            do {
                try await installProfile(profile)
                if await !settleOnDemandEdit(id) {
                    operationMessage = Self.onDemandFailedMessage
                }
            } catch { operationMessage = Self.onDemandFailedMessage }
        }
    }

    /// Arms the tunnel's manager when its saved on-demand options hold any rule and disarms it otherwise, never starting
    /// or stopping the tunnel. False when the backend could not update it; a backend without managers has nothing to do.
    func followOnDemandRules(_ id: UUID) async -> Bool {
        guard let activation = backend as? any OnDemandActivation else { return true }
        do {
            try await activation.followOnDemandRules(id)
            return true
        } catch { return false }
    }

    /// Reads the current SSID for "Add current network". iOS answers an app whose VPN configuration is installed, with no
    /// location prompt; the fake backend installs none, so it offers nothing.
    var connectedNetwork: (() async -> ConnectedNetworkReading)? {
        guard backend != nil, !usesFakeBackend else { return nil }
        return {
            await withCheckedContinuation { continuation in
                NEHotspotNetwork.fetchCurrent { network in
                    let ssid = network?.ssid ?? ""
                    continuation.resume(returning: ssid.isEmpty ? .unreadable : .ssid(ssid))
                }
            }
        }
    }

    /// Ends a pending move of the earlier app-wide on-demand policy; the next preferences write leaves it out.
    func clearLegacyOnDemand() {
        pendingLegacyOnDemand = nil
        pendingLegacyProfileID = nil
    }
}
