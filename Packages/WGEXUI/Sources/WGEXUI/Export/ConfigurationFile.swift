// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
#if os(macOS)
    import Darwin
#elseif os(iOS)
    import SwiftUI
    import UniformTypeIdentifiers
#endif

#if os(macOS)
    public extension ExportModel {
        /// Writes beside the destination with 0600 from creation, then atomically replaces it.
        /// No intermediate Foundation Data/String contains the private key.
        @discardableResult
        func writeConfirmedFile(to selectedURL: URL) throws -> URL {
            let text = try confirmedFileText()
            let destination = selectedURL.pathExtension.lowercased() == "conf" ? selectedURL : selectedURL.appendingPathExtension("conf")
            guard destination.isFileURL else { throw ExportError.fileWriteFailed }
            let temporary = destination.deletingLastPathComponent().appendingPathComponent(".wgex-\(UUID().uuidString)")
            let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard descriptor >= 0 else { throw ExportError.fileWriteFailed }
            defer { close(descriptor); unlink(temporary.path) }
            guard fchmod(descriptor, mode_t(0o600)) == 0 else { throw ExportError.fileWriteFailed }
            try text.bytes.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let count = write(descriptor, raw.baseAddress?.advanced(by: offset), raw.count - offset)
                    if count < 0, errno == EINTR {
                        continue
                    }
                    guard count > 0 else { throw ExportError.fileWriteFailed }
                    offset += count
                }
            }
            guard fsync(descriptor) == 0, rename(temporary.path, destination.path) == 0 else { throw ExportError.fileWriteFailed }
            return destination
        }
    }
#elseif os(iOS)
    /// Immutable bytes can be borrowed by the document exporter on any executor.
    /// SwiftUI may make transient Foundation copies when writing the file.
    package final nonisolated class SecretExportStorage: Sendable {
        package let text: SecretText
        package init(_ text: consuming SecretText) {
            self.text = text
        }
    }

    package nonisolated struct ConfigurationFile: FileDocument {
        package static let contentType = UTType(importedAs: "com.wireguard.config", conformingTo: .plainText)
        package static let readableContentTypes: [UTType] = [contentType]
        private let storage: SecretExportStorage

        package init(_ text: consuming SecretText) {
            storage = SecretExportStorage(consume text)
        }

        package init(configuration: ReadConfiguration) throws {
            throw ExportError.unsupportedPlatform
        }

        package func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
            let data = storage.text.bytes.withUnsafeBytes { Data($0) }
            let wrapper = FileWrapper(regularFileWithContents: data)
            wrapper.preferredFilename = "WireGuard.conf"
            wrapper.fileAttributes = [FileAttributeKey.posixPermissions.rawValue: 0o600]
            return wrapper
        }
    }
#endif
