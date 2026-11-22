// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation

/// Errors contain no caller text, paths, platform errors or secrets.
public enum DiagnosticsError: Error, Sendable { case sizeLimit, sectionUnavailable, encodingFailed }

/// Integration seam for system information, key-free profile summaries, routes, DNS and pf.
/// Implementations must bound collection; the builder redacts every returned section.
public protocol DiagnosticsSectionSource: Sendable {
    func diagnosticsSections() throws -> [DiagnosticsSection]
}

/// Section names are deliberately constrained; user names never become ZIP paths.
public struct DiagnosticsSection: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Kind: String, Sendable, CaseIterable {
        case systemInfo, profileSummaries, pf, routes, dns, provider
    }

    public var description: String {
        "<DiagnosticsSection>"
    }

    public var debugDescription: String {
        description
    }

    public let kind: Kind
    private let text: String
    public init(kind: Kind, text: String) {
        self.kind = kind; self.text = text
    }

    fileprivate func redacted(using redactor: Redactor) -> Data {
        Data(redactor.redact(text).utf8)
    }
}

/// Vocabulary mirrors the daemon wire shape without a backend dependency.
public struct DiagnosticsArchive: Sendable {
    public let createdAt: Date
    public let archive: Data
    public let filename: String
}

/// Foundation-only collection seams and a native stored-ZIP writer; usable in extensions.
/// The daemon must apply per-uid filtering before supplying rings and sections.
public struct DiagnosticsBundleBuilder: Sendable {
    public static let maximumBytes = 10 * 1024 * 1024
    private let redactor: Redactor
    public init(redactor: Redactor) {
        self.redactor = redactor
    }

    public func build(
        rings: [LogRing], sources: [any DiagnosticsSectionSource] = [], createdAt: Date = Date(),
    ) throws(DiagnosticsError) -> DiagnosticsArchive {
        var entries: [StoredZIP.Entry] = []
        var total = 0
        func add(_ name: String, data: Data) throws(DiagnosticsError) {
            guard data.count <= Self.maximumBytes - total else { throw .sizeLimit }
            total += data.count; entries.append(StoredZIP.Entry(name: name, data: data))
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        for (index, ring) in rings.enumerated() {
            do { try add("logs/process-\(index).json", data: encoder.encode(ring.redactedLines(using: redactor))) }
            catch let error as DiagnosticsError { throw error }
            catch { throw .encodingFailed }
        }
        for (index, source) in sources.enumerated() {
            let sections: [DiagnosticsSection]
            do { sections = try source.diagnosticsSections() } catch { throw .sectionUnavailable }
            for (sectionIndex, section) in sections.enumerated() {
                try add("sections/\(index)-\(section.kind.rawValue)-\(sectionIndex).txt", data: section.redacted(using: redactor))
            }
        }
        let hashes = entries.sorted(by: { $0.name < $1.name }).map {
            ManifestEntry(name: $0.name, sha256: SHA256.hash(data: $0.data).map { String(format: "%02x", $0) }.joined())
        }
        do { try add("manifest.json", data: encoder.encode(Manifest(version: 1, entries: hashes))) }
        catch let error as DiagnosticsError { throw error }
        catch { throw .encodingFailed }
        let archive = try StoredZIP.archive(entries, maximumBytes: Self.maximumBytes)
        // ZIP metadata is fixed at 1980-01-01; only the download filename uses the supplied date.
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]; formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return DiagnosticsArchive(
            createdAt: createdAt,
            archive: archive,
            filename: "wgex-diagnostics-\(formatter.string(from: createdAt)).zip",
        )
    }
}

private struct Manifest: Encodable {
    let version: Int
    let entries: [ManifestEntry]
}

private struct ManifestEntry: Encodable {
    let name: String
    let sha256: String
}
