// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import WGEXAppComposition
import WGEXCore
import WGEXProfileStore
import WGEXUI
#if DEBUG || WGEX_LAB_BUILD
    import WGEXTesting
#endif

/// Fixed, payload-free copy for every refused source. No message carries a name, a path or configuration text.
internal nonisolated enum IOSImportMessage {
    internal static let notConfiguration = "That is not a WireGuard configuration."
    internal static let notQRConfiguration = "That QR code is not a WireGuard configuration."
    internal static let tooLarge = "That file is too large to import."
    internal static let unreadableFile = "That file could not be read."
    internal static let badArchive = "That archive could not be read. Choose a ZIP of .conf files."
    internal static let cameraDenied = "Camera access is off. Allow WGEX to use the camera in Settings, or add the tunnel another way."
    internal static let cameraUnavailable = "No camera is available on this device."
    internal static let unreadableCode = "That code could not be read. Hold the camera steady and try again."
}

internal extension AppModel {
    // MARK: Sources

    /// Paste: the text becomes a review named "Imported profile".
    func prepareImport(_ text: String) {
        var bytes = Array(text.utf8)
        beginImport()
        guard bytes.count <= IOSImportSources.maximumConfigurationBytes else {
            wipe(&bytes); operationMessage = IOSImportMessage.tooLarge; return
        }
        reviewQueue = [makeReview(&bytes, name: Self.defaultImportName)]
        reviewPublished()
    }

    /// A scanned QR payload. Anything without an interface section is refused with its own message.
    func prepareScannedCode(_ payload: String) {
        var bytes = Array(payload.utf8)
        beginImport()
        guard IOSImportSources.looksLikeConfiguration(bytes) else {
            wipe(&bytes); operationMessage = IOSImportMessage.notQRConfiguration; return
        }
        guard bytes.count <= IOSImportSources.maximumConfigurationBytes else {
            wipe(&bytes); operationMessage = IOSImportMessage.tooLarge; return
        }
        reviewQueue = [makeReview(&bytes, name: Self.defaultImportName)]
        reviewPublished()
    }

    /// A scanner that could not deliver a payload shows its own plain message and never starts a review.
    func reportScanFailure(_ failure: IOSScanFailure) {
        beginImport()
        switch failure {
        case .cameraDenied: operationMessage = IOSImportMessage.cameraDenied
        case .cameraUnavailable: operationMessage = IOSImportMessage.cameraUnavailable
        case .unreadable: operationMessage = IOSImportMessage.unreadableCode
        }
    }

    /// Files picker, Open In and the share sheet all land here. The size is checked before any byte is read.
    func importFile(at url: URL) {
        defer { IOSImportSources.removeStagedCopy(url) }
        do {
            var data = try IOSImportSources.load(url)
            defer { data.resetBytes(in: 0 ..< data.count) }
            importFile(data, name: url.deletingPathExtension().lastPathComponent, isArchive: url.pathExtension.lowercased() == "zip")
        } catch IOSImportSources.Failure.tooLarge {
            beginImport(); operationMessage = IOSImportMessage.tooLarge
        } catch {
            beginImport(); operationMessage = IOSImportMessage.unreadableFile
        }
    }

    /// Injected-bytes entry point for a `.conf` or `.zip`. A ZIP is recognised by its extension or its signature.
    func importFile(_ data: Data, name: String, isArchive: Bool) {
        beginImport()
        guard data.count <= IOSImportSources.maximumBytes else { operationMessage = IOSImportMessage.tooLarge; return }
        if isArchive || IOSImportSources.isArchive(data) {
            importArchive(data)
            return
        }
        guard data.count <= IOSImportSources.maximumConfigurationBytes else {
            operationMessage = IOSImportMessage.tooLarge; return
        }
        var bytes = Array(data)
        guard IOSImportSources.looksLikeConfiguration(bytes) else {
            wipe(&bytes); operationMessage = IOSImportMessage.notConfiguration; return
        }
        reviewQueue = [makeReview(&bytes, name: Self.reviewName(name))]
        reviewPublished()
    }

    /// Every configuration in the archive gets its own review; the archive is refused whole when it cannot be read.
    private func importArchive(_ data: Data) {
        var staged: [ImportReviewModel] = []
        do {
            try IOSImportSources.scan(data) { name, bytes in
                staged.append(makeReview(&bytes, name: Self.reviewName(name)))
            }
            reviewQueue = staged
            reviewPublished()
        } catch IOSImportSources.Failure.tooLarge {
            operationMessage = IOSImportMessage.tooLarge
        } catch { operationMessage = IOSImportMessage.badArchive }
    }

    /// An empty editor with a generated key pair; the first save adds the profile.
    func createFromScratch() {
        beginImport()
        var profile = TunnelProfile(name: "New tunnel")
        profile.onDemand = onDemand
        profile.protection = protection
        let model = ProfileEditorModel(profile: profile, featureFlags: featureFlags)
        model.generateKeypair()
        guard !model.actionFailed else { operationMessage = "A key pair could not be generated. Try again."; return }
        editor = model
    }

    func prepareFixture() {
        #if DEBUG || WGEX_LAB_BUILD
            do {
                var bytes = try GeneratedFixture.configurationBytes()
                beginImport()
                reviewQueue = [makeReview(&bytes, name: Self.defaultImportName)]
                reviewPublished()
            } catch { operationMessage = "The example could not be generated." }
        #else
            operationMessage = "The example profile is only available in test builds."
        #endif
    }

    // MARK: Review queue

    /// Every review still waiting, the current one first, for the ticked list of a zip import.
    var pendingReviews: [ImportReviewModel] {
        reviewQueue
    }

    /// Drops the current review (a refused entry, or one the user does not want) and moves on to the next.
    func skipReview() {
        guard !reviewQueue.isEmpty, !isBusy else { return }
        advanceReview()
        operationMessage = nil
    }

    func cancelImport() {
        reviewQueue = []
        importDiagnostics = []
        operationMessage = nil
    }

    func confirmImport() async {
        guard let review, review.canImport, !isBusy else { return }
        var prepared: ProfileEditorModel?
        review.confirm { profile, secrets in
            prepared = try ProfileEditorModel(profile: profile, secrets: secrets, featureFlags: featureFlags)
        }
        guard let prepared else { return }
        await commitImport(prepared, connect: false)
    }

    func importReviewed(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets, connect: Bool) throws {
        guard !isBusy else { throw TunnelError.cancelled }
        let prepared = try ProfileEditorModel(profile: profile, secrets: secrets, featureFlags: featureFlags)
        Task { await commitImport(prepared, connect: connect) }
    }

    /// Removes the finished review; later reviews see the profiles saved so far, so name and key clashes follow the review rules.
    func advanceReview() {
        if !reviewQueue.isEmpty {
            reviewQueue.removeFirst()
        }
        for pending in reviewQueue {
            pending.existingProfiles = profiles
        }
        importDiagnostics = review?.diagnostics ?? []
    }

    // MARK: Helpers

    static let defaultImportName = "Imported profile"

    /// A file or entry name becomes the profile name, limited to what the parser accepts.
    static func reviewName(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return defaultImportName }
        return String(trimmed.prefix(ParseLimits.default.maximumNameCharacters))
    }

    private func beginImport() {
        reviewQueue = []
        importDiagnostics = []
        operationMessage = nil
    }

    private func reviewPublished() {
        importDiagnostics = review?.diagnostics ?? []
    }

    private func wipe(_ bytes: inout [UInt8]) {
        _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }

    /// Parses one payload in place and wipes it. The caller passes uniquely owned storage so no second copy is made.
    private func makeReview(_ bytes: inout [UInt8], name: String) -> ImportReviewModel {
        defer { wipe(&bytes) }
        do {
            let parsed = try parseWgQuick(&bytes, name: name)
            var profile = parsed.profile
            profile.onDemand = onDemand
            profile.protection = protection
            if !profile.interface.addresses.contains(where: \.isIPv6) {
                profile.protection.ipv6Policy = .blockOutside
            }
            setFailover(&profile)
            let reviewed = try ParsedConfiguration(
                profile: profile,
                diagnostics: parsed.diagnostics.filter { $0.code != .ipv6PolicyRequired },
                secrets: ProfileComposition.copySecrets(parsed.secrets),
                original: parsed.original,
            )
            return ImportReviewModel(parsed: reviewed, existingProfiles: profiles)
        } catch let error as ConfigParseError {
            return ImportReviewModel(parseError: error, name: name, existingProfiles: profiles)
        } catch {
            return ImportReviewModel(parseError: error, name: name, existingProfiles: profiles)
        }
    }
}
