// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import WGEXDaemonCore
import WGEXDaemonProtocol

/// Dedicated PF journal in a caller-owned secure state directory. The controller may
/// instead inject its shared journal. Tokens are written 0600, synced, then renamed;
/// the parent directory is synced before success. No target symlink is followed.
public struct PFFileTokenJournal: PFTokenJournalling {
    private struct Record: Codable {
        let version: Int; let pfToken: String?; let bootSession: UUID?; let pid: Int32?; let attempt: PFEnableAttempt?
    }

    /// Caller-owned temporary journal location.
    public let url: URL
    /// Creates the inert fixture with explicitly supplied state.
    public init(url: URL) {
        self.url = url
    }

    /// Reads the legacy fixture journal without following a target symlink.
    public func readState() throws -> PFTokenState {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        if descriptor < 0, errno == ENOENT {
            return PFTokenState()
        }
        guard descriptor >= 0 else { throw DaemonFailure.pfJournal }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_uid == getuid(), info.st_size <= 4096
        else { throw DaemonFailure.pfJournal }
        let record = try JSONDecoder().decode(Record.self, from: handle.readToEnd() ?? Data())
        guard record.version == 1, record.pfToken.map(PacketFilterReadback.validToken) != false else {
            throw DaemonFailure.pfJournal
        }
        return PFTokenState(token: record.pfToken, bootSession: record.bootSession, pid: record.pid, attempt: record.attempt)
    }

    /// Reads the numeric fixture reference from its journal.
    public func readToken() throws -> String? {
        try readState().token
    }

    /// Persists the selected fixture reference in the caller-owned journal.
    public func writeToken(_ token: String?) throws {
        var state = (try? readState()) ?? PFTokenState()
        if state.token != token {
            state.bootSession = nil; state.pid = nil
        }
        state.token = token
        try writeState(state)
    }

    /// Atomically persists fixture ownership state in the caller-owned journal.
    public func writeState(_ state: PFTokenState) throws {
        let token = state.token
        guard token.map(PacketFilterReadback.validToken) != false else { throw DaemonFailure.pfToken }
        let data = try JSONEncoder().encode(Record(
            version: 1,
            pfToken: token,
            bootSession: state.bootSession,
            pid: state.pid,
            attempt: state.attempt,
        ))
        let directory = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard directory >= 0 else { throw DaemonFailure.pfJournal }
        defer { close(directory) }
        let temporary = ".wgex-pf-\(UUID().uuidString).json"
        let descriptor = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw DaemonFailure.pfJournal }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer {
            try? handle.close()
            unlinkat(directory, temporary, 0)
        }
        try handle.write(contentsOf: data)
        try handle.synchronize()
        guard renameat(directory, temporary, directory, url.lastPathComponent) == 0, fsync(directory) == 0 else {
            throw DaemonFailure.pfJournal
        }
    }
}
