// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXDiagnostics

/// Rings are partitioned at ingestion; a mixed process ring must never be passed to the archive builder.
public final class DaemonDiagnosticsAdapter: DaemonDiagnosticsProviding {
    private struct Rings: Sendable {
        let global = LogRing()
        var profiles: [UUID: LogRing] = [:]
        var changes = DaemonDiagnosticChanges()
    }

    private let rings = Mutex(Rings())
    private let redactor = Redactor()
    private let sections: @Sendable () async throws -> [DiagnosticsSection]
    private struct ExportState { var available = true; var failures: UInt64 = 0 }
    private let exportState = Mutex(ExportState())
    private let preparation = Mutex<(@Sendable () async throws -> Void)?>(nil)

    /// Sources run only when exporting; tests inject bounded text and never invoke host adapters.
    public init(sections: @escaping @Sendable () async throws -> [DiagnosticsSection] = { [] }) {
        self.sections = sections
    }

    /// Preserves the concrete diagnostics boundary for deferred profile registration.
    public func sectionUnavailableFailure() -> any Error {
        DiagnosticsError.sectionUnavailable
    }

    #if os(macOS)
        /// Redacts a system snapshot only after PF availability and section bounds have been checked.
        public static func system(snapshot: @escaping @Sendable () async throws -> DaemonSystemSnapshot) -> DaemonDiagnosticsAdapter {
            DaemonDiagnosticsAdapter(sections: {
                let sections = try await snapshot()
                guard sections.pf.status == 0, sections.pf.stdout.utf8.count <= 1 << 20 else {
                    throw DiagnosticsError.sectionUnavailable
                }
                guard sections.routes.count <= 1 << 20, sections.dns.utf8.count <= 1 << 20 else { throw DiagnosticsError.sizeLimit }
                return [
                    .init(kind: .pf, text: sections.pf.stdout),
                    .init(kind: .routes, text: String(decoding: sections.routes, as: UTF8.self)),
                    .init(kind: .dns, text: sections.dns),
                ]
            })
        }
    #endif

    /// A failed startup registration must not produce an incompletely registered archive.
    public func disableExports() {
        exportState.withLock { $0.available = false; $0.failures &+= 1 }
    }

    /// Late wiring avoids a registry/adapter ownership cycle; a failed registration is retried on export.
    public func setPreparation(_ action: @escaping @Sendable () async throws -> Void) {
        preparation.withLock { $0 = action }
    }

    /// Register every installed profile, including other owners, before collecting global system sections.
    public func register(_ profile: TunnelProfile) {
        redactor.register([profile.name] + profile.interface.dns.map(\.stringRepresentation)
            + profile.interface.searchDomains + profile.peers.compactMap { $0.endpoint?.host })
    }

    /// Retains only keyed fingerprints; temporary secret exports stay in wiped allocations.
    public func registerSecretWire(_ wire: borrowing SecretBytes) throws {
        do { try registerSecrets(wire) }
        catch { disableExports(); throw error }
    }

    private func registerSecrets(_ wire: borrowing SecretBytes) throws {
        let bundle = try SecretsWireLayout.decode(SecretBytes(parsing: wire))
        try registerKey(bundle.privateKey())
        for peer in bundle.presharedKeyPeers {
            if let key = try bundle.presharedKey(for: peer) {
                try registerKey(key)
            }
        }
        for id in bundle.carrierIDs {
            if let credential = try bundle.carrierCredential(for: id) {
                redactor.register(credential)
            }
        }
    }

    private func registerKey(_ key: consuming SecretBytes) throws {
        redactor.register(key)
        for encoding in [KeyEncoding.base64, .hex] {
            var encoded = try SecretBytes(zeroedCount: ByteCodec.encodedCount(key.count, encoding: encoding))
            try unsafe key.withUnsafeBytes { raw in
                try unsafe encoded.withUnsafeMutableBytes { try unsafe ByteCodec.encode(raw, into: $0, encoding: encoding) }
            }
            redactor.register(encoded)
        }
    }

    public func record(_ event: DaemonServiceEvent) async -> RedactedLogLine? {
        // Only fixed state vocabulary enters these rings. No request, profile document, UAPI or error text.
        let message: String
        switch event.event {
        case .status: message = "Tunnel status changed"
        case .needsSecrets: message = "Open WGEX to reconnect"
        default: return nil
        }
        let ring: LogRing? = rings.withLock { state in
            guard state.changes.receive(event) else { return nil }
            guard let id = event.profileID else { return state.global }
            if let ring = state.profiles[id] {
                return ring
            }
            let ring = LogRing(); state.profiles[id] = ring; return ring
        }
        guard let ring else { return nil }
        #if WGEX_LAB_BUILD
            if case let .status(status) = event.event {
                DaemonDiagnostics.status(status)
            }
        #endif
        let date = Date()
        ring.append(message, category: .daemon, date: date)
        return RedactedLogLine(date: date, category: "daemon", message: message, profileID: event.profileID)
    }

    /// Raw engine text enters the ring only; `logs` redacts it on the way out. A line beyond `engineLineByteLimit` is cut
    /// before storage so one line cannot evict the ring; the cut also drops the trailing run of key-alphabet characters, so
    /// a key split by the cut leaves no fragment too short for the redactor to recognise.
    public func recordEngine(_ message: String, date: Date, profileID: UUID?) {
        let ring: LogRing = rings.withLock { state in
            guard let id = profileID else { return state.global }
            if let ring = state.profiles[id] {
                return ring
            }
            let ring = LogRing(); state.profiles[id] = ring; return ring
        }
        var text = message
        if text.utf8.count > Self.engineLineByteLimit {
            text = Self.prefix(text, bytes: Self.engineLineByteLimit)
            while let last = text.unicodeScalars.last, Self.keyAlphabet.contains(last) {
                text.unicodeScalars.removeLast()
            }
        }
        ring.append(text, category: .engine, date: date)
    }

    /// Longest engine line kept; wireguard-go lines are far shorter.
    public static let engineLineByteLimit = 2048
    /// Longest redacted message one `logs` reply carries per line.
    public static let replyLineByteLimit = 512
    /// Message bytes plus a fixed per-line allowance that one `logs` reply may carry, well inside the XPC payload limit.
    public static let replyByteBudget = 128 * 1024
    private static let replyLineOverhead = 160
    /// Base64, base64url and hexadecimal characters.
    private static let keyAlphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")

    private static func prefix(_ text: String, bytes limit: Int) -> String {
        guard text.utf8.count > limit else { return text }
        var end = text.startIndex, used = 0
        for scalar in text.unicodeScalars {
            let next = used + scalar.utf8.count
            guard next <= limit else { break }
            used = next; end = text.unicodeScalars.index(after: end)
        }
        return String(Substring(text.unicodeScalars[..<end]))
    }

    private func scoped(_ visible: Set<UUID>) -> [(UUID?, LogRing)] {
        rings.withLock { state in
            [(nil, state.global)] + visible.sorted { $0.uuidString < $1.uuidString }.compactMap { id in
                state.profiles[id].map { (id, $0) }
            }
        }
    }

    /// Newest lines last; at most `limit` (capped at 512) and `replyByteBudget`, each message redacted before it is cut to
    /// `replyLineByteLimit`, so the reply always fits one XPC payload.
    public func logs(since: Date?, limit: Int, visibleProfileIDs: Set<UUID>) async throws -> [RedactedLogLine] {
        let lines = scoped(visibleProfileIDs).flatMap { id, ring in
            ring.redactedLines(using: redactor).filter { line in since.map { line.date >= $0 } ?? true }.map { line in
                RedactedLogLine(
                    date: line.date,
                    category: line.category,
                    message: Self.prefix(line.message, bytes: Self.replyLineByteLimit),
                    profileID: id,
                )
            }
        }.sorted { $0.date < $1.date }.suffix(max(0, min(limit, 512)))
        var kept: [RedactedLogLine] = [], used = 0
        for line in lines.reversed() {
            used += line.message.utf8.count + Self.replyLineOverhead
            guard used <= Self.replyByteBudget else { break }
            kept.append(line)
        }
        return kept.reversed()
    }

    public func bundle(_ request: DiagnosticsRequest, visibleProfileIDs: Set<UUID>) async throws -> DiagnosticsBundle {
        if let prepare = preparation.withLock({ $0 }) {
            let before = exportState.withLock { $0.failures }
            do {
                try await prepare()
                exportState.withLock {
                    if $0.failures == before {
                        $0.available = true
                    }
                }
            } catch { throw DiagnosticsError.sectionUnavailable }
        }
        guard exportState.withLock({ $0.available }) else { throw DiagnosticsError.sectionUnavailable }
        // An empty list means every profile the caller owns (DiagnosticsRequest.profileIDs), never none.
        let visible = request.profileIDs.isEmpty ? visibleProfileIDs : visibleProfileIDs.intersection(request.profileIDs)
        let filtered = LogRing()
        if request.includeLogs {
            for line in try await logs(since: request.since, limit: 512, visibleProfileIDs: visible) {
                filtered.append(line.message, category: .daemon, date: line.date)
            }
        }
        let source = try await CollectedDaemonSections(sections: sections())
        let archive = try DiagnosticsBundleBuilder(redactor: redactor).build(
            rings: request.includeLogs ? [filtered] : [],
            sources: [source],
        )
        return DiagnosticsBundle(createdAt: archive.createdAt, archive: archive.archive)
    }
}

private struct CollectedDaemonSections: DiagnosticsSectionSource {
    let sections: [DiagnosticsSection]
    func diagnosticsSections() -> [DiagnosticsSection] {
        sections
    }
}
