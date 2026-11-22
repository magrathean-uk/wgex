// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Foundation
    import UniformTypeIdentifiers
    import WGEXCore
    import WGEXProfileStore
    import WGEXUI

    /// The Add a Tunnel actions setup step 3 hands to the main window.
    public enum MacSetupAddAction: Equatable, Sendable {
        case chooseFile, paste, createEmpty, drop([URL])
    }

    public extension MacAppModel {
        func openImport() {
            importReviews = []; importErrorMessage = nil; importing = true
        }

        /// The menu bar and the File menu open the window's own importer, then bring the window forward.
        func openImportInMainWindow(show: () -> Void) {
            openImport(); show()
        }

        /// Setup step 3 (SPEC 7): a row or a dropped file closes setup first; the main window runs the action once the
        /// setup sheet has gone (`setupSheetDismissed`), so its Review, Edit or picker never stacks on the setup sheet.
        func leaveSetup(then action: MacSetupAddAction) {
            pendingSetupAction = action
            shell.routeWindow(.importTunnel)
        }

        /// The setup sheet has gone; a pending step 3 action runs now in the main window.
        func setupSheetDismissed() {
            guard let action = pendingSetupAction else { return }
            pendingSetupAction = nil
            switch action {
            case .chooseFile: chooseImportFile()
            case .paste: pasteImport()
            case .createEmpty: openNewProfile()
            case let .drop(urls): importURLs(urls)
            }
        }

        func cancelImport() {
            importing = false; importReviews = []; importErrorMessage = nil
        }

        /// Import from File…: the file picker, then Review Tunnel for what it returns. No image or QR source on the Mac (D8).
        func chooseImportFile() {
            // A fresh import (menu, empty page, setup) starts clean; an open Add sheet keeps the reviews it already holds.
            if !importing {
                importReviews = []; importErrorMessage = nil
            }
            let panel = NSOpenPanel()
            panel.allowedContentTypes = [.data, .zip]
            panel.allowsMultipleSelection = true
            guard panel.runModal() == .OK else { return }
            importURLs(panel.urls)
        }

        /// Paste from Clipboard: Review Tunnel for a configuration, otherwise one line saying the clipboard holds none
        /// (in the Add sheet when it is open, else as the window's message).
        func pasteImport() {
            guard let text = NSPasteboard.general.string(forType: .string),
                  text.range(of: "[interface]", options: .caseInsensitive) != nil
            else {
                importErrorMessage = MacStrings.clipboardHoldsNoConfiguration
                if !importing {
                    shell.reportClipboardWithoutConfiguration()
                }
                return
            }
            importErrorMessage = nil
            var bytes = Array(text.utf8)
            reviewBytes(&bytes, name: "Imported tunnel")
        }

        /// Create Empty Tunnel from the Add sheet: the sheet closes first, then its dismissal opens the editor
        /// (`importSheetDismissed`), so two sheets are never presented from the same window at once.
        func createEmptyTunnel() {
            pendingEmptyTunnel = true
            importing = false; importReviews = []; importErrorMessage = nil
        }

        /// The Add or Review sheet has gone; a pending Create Empty Tunnel opens the editor now.
        func importSheetDismissed() {
            guard pendingEmptyTunnel else { return }
            pendingEmptyTunnel = false
            openNewProfile()
        }

        func importURLs(_ urls: [URL]) {
            // A line about an earlier source (an empty clipboard, an unreadable file) does not describe these files.
            importErrorMessage = nil
            importing = true
            for url in urls.prefix(64) {
                do {
                    let access = url.startAccessingSecurityScopedResource()
                    defer {
                        if access {
                            url.stopAccessingSecurityScopedResource()
                        }
                    }
                    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                    guard let size = attributes[.size] as? NSNumber, size.intValue <= MacImportSources.maximumBytes else {
                        throw MacImportSources.Failure.tooLarge
                    }
                    var data = try Data(contentsOf: url)
                    defer { data.resetBytes(in: 0 ..< data.count) }
                    if url.pathExtension.lowercased() == "zip" {
                        // One bad entry still refuses the whole archive: stage the small parsed reviews, publish on success.
                        var staged: [ImportReviewModel] = []
                        try MacImportSources.scan(data) { name, bytes in staged.append(makeReview(&bytes, name: name)) }
                        importReviews.append(contentsOf: staged)
                        importing = true
                    } else {
                        var bytes = Array(data)
                        reviewBytes(&bytes, name: url.deletingPathExtension().lastPathComponent)
                    }
                } catch {
                    importErrorMessage = MacAppErrorCopy.resolve(MacWorkflowError.importSource).message
                    shell.reportError(MacWorkflowError.importSource)
                }
            }
        }

        private func reviewBytes(_ bytes: inout [UInt8], name: String) {
            importReviews.append(makeReview(&bytes, name: name))
            importing = true
        }

        /// Parses one payload in place and zeroes it; the caller passes uniquely owned storage so no second copy is made.
        private func makeReview(_ bytes: inout [UInt8], name: String) -> ImportReviewModel {
            defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            do {
                let parsed = try parseWgQuick(&bytes, name: name)
                return ImportReviewModel(parsed: consume parsed, existingProfiles: shell.profiles)
            } catch { return ImportReviewModel(parseError: error, name: name, existingProfiles: shell.profiles) }
        }
    }
#endif
