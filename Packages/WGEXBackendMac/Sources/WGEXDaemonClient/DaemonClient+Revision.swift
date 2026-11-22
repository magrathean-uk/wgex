// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

extension DaemonClient {
    package func installDocument(_ document: TunnelProfile) async throws {
        guard !conflictedProfiles.contains(document.id) else { throw DaemonError.tunnel(.revisionConflict) }
        if revisions[document.id] == nil {
            try await refreshRevision(document.id)
        }
        let requestEpoch = epoch
        let reply: Reply
        do { reply = try await request(.installProfileCAS(document, expectedRevision: revisions[document.id])) }
        catch let error as DaemonError where ![.disconnected, .malformedMessage, .tunnel(.timedOut)].contains(error) { throw error }
        catch { revisions[document.id] = nil; throw error }
        guard epoch == requestEpoch else { revisions[document.id] = nil; throw DaemonError.disconnected }
        if case .profileRevisionConflict = reply {
            throw DaemonError.tunnel(.revisionConflict)
        }
        guard case let .profileRevision(revision?) = reply else { revisions[document.id] = nil; throw DaemonError.malformedMessage }
        revisions[document.id] = revision
    }

    /// Explicit reload clears a conflict only after reading the revision; review the profile before saving.
    @discardableResult public func refreshRevision(_ id: UUID) async throws -> UInt64? {
        guard case let .profileRevision(current) = try await request(.profileRevision(id)) else { throw DaemonError.malformedMessage }
        revisions[id] = current
        conflictedProfiles.remove(id)
        return current
    }
}
