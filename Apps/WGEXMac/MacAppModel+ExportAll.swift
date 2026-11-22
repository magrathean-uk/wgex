// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Foundation
    import UniformTypeIdentifiers
    import WGEXCore
    import WGEXUI

    /// Export of every tunnel into one official-layout .zip. Keys never leave `SecretText` buffers.
    public extension MacAppModel {
        /// Opens the key warning. Nothing is read or written until `confirmExportAll()`.
        func requestExportAll() {
            guard !shell.profiles.isEmpty, !exportAllRunning else { return }
            exportAllMessage = nil; exportAllConfirming = true
        }

        func cancelExportAll() {
            exportAllConfirming = false
        }

        /// Takes the confirmed warning to the save panel, then writes the archive.
        func confirmExportAll() {
            exportAllConfirming = false
            let panel = NSSavePanel()
            panel.nameFieldStringValue = MacStrings.exportAllFilename
            panel.allowedContentTypes = [.zip]
            guard panel.runModal() == .OK, let url = panel.url else { return }
            Task { await exportAll(to: url) }
        }

        /// Writes the archive and reports only fixed copy on failure. Returns whether the file was written.
        @discardableResult
        func exportAll(to url: URL) async -> Bool {
            guard !exportAllRunning else { return false }
            let profiles = shell.profiles.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            exportAllRunning = true; exportAllMessage = nil
            defer { exportAllRunning = false }
            do {
                try await MacTunnelArchive.write(names: profiles.map(\.name), to: url) { index in
                    // The single-profile export path, so keys are serialised exactly as that flow does.
                    let secrets = try await self.storedSecrets(profiles[index])
                    let model = ExportModel(profile: profiles[index], secrets: secrets)
                    model.request(.file); model.confirm()
                    return try model.confirmedFileText()
                }
                return true
            } catch {
                exportAllMessage = Self.exportAllCopy(error)
                return false
            }
        }

        private static func exportAllCopy(_ error: any Error) -> String {
            switch error as? MacTunnelArchive.Failure {
            case .tooManyTunnels: MacStrings.exportAllTooMany
            case .tooLarge: MacStrings.exportAllTooLarge
            default: MacStrings.theConfigurationCouldNotBe
            }
        }
    }
#endif
