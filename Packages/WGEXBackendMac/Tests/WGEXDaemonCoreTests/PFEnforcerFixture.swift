// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

package final class PFMemoryJournal: PFTokenJournalling {
    private let value = Mutex(PFTokenState())
    package let failWrite: Bool
    package init(failWrite: Bool = false, token: String? = nil) {
        self.failWrite = failWrite
        value.withLock { $0 = PFTokenState(token: token, bootSession: try? SystemBootSession.read(), pid: 123) }
    }

    package func readState() -> PFTokenState {
        value.withLock { $0 }
    }

    package func writeState(_ state: PFTokenState) throws {
        guard !failWrite else { throw DaemonFailure.pfJournal }
        value.withLock { $0 = state }
    }

    package func readToken() -> String? {
        value.withLock { $0.token }
    }

    package func writeToken(_ token: String?) throws {
        if failWrite {
            throw DaemonFailure.pfJournal
        }
        value.withLock { $0.token = token }
    }
}

package actor PFScriptedSystem: PacketFilterSystem {
    package var calls: [[String]] = []
    package var loaded = ""
    package var mismatch = false
    package var missingStock = false
    package var canary: UInt64 = 0
    package var disabled = false
    package var failRelease = false
    package var timeoutLoad = false
    private var failEndpoints = false
    private var badTable = false
    private var ownedReference = true
    package func failEndpointLoad() {
        failEndpoints = true
    }

    package func setTableMismatch() {
        badTable = true
    }

    package func releaseOwnedReference() {
        ownedReference = false
    }

    package func probe() {
        if !disabled {
            canary += 1
        }
    }

    package func timeOutNextLoad() {
        timeoutLoad = true
    }

    private let journal: PFMemoryJournal
    package private(set) var journalWasWrittenBeforeLoad = false
    package init(journal: PFMemoryJournal) {
        self.journal = journal
    }

    package func setDisabled() {
        disabled = true
    }

    package func setFailRelease() {
        failRelease = true
    }

    package func setMismatch() {
        mismatch = true
    }

    package func setMissingStock() {
        missingStock = true
    }

    package func setCanary(_ value: UInt64) {
        canary = value
    }

    package func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult {
        try beforeExec(123)
        return try run(arguments: ["-E"], input: Data(), deadline: deadline)
    }

    private func scriptedResult(_ arguments: [String], input: Data) -> PFCommandResult? {
        if failEndpoints, arguments.contains("-f"), String(decoding: input, as: UTF8.self).contains("port 51820") {
            return PFCommandResult(status: 2, stderr: "pfctl: DIOCADDRULE: Device not configured")
        }
        if arguments.contains("-T"), arguments.last == "show" {
            return PFCommandResult(stdout: badTable ? "192.0.2.0/24\n" : pfTableOutput(loaded))
        }
        return nil
    }

    private func referenceResult() throws -> PFCommandResult {
        try PFCommandResult(
            stdout: PFTranscripts.references([
                .init(pid: 456, process: "pfctl", token: "12345", age: 1),
            ] + (ownedReference ? [.init(pid: 123, token: "99")] : [])),
            stderr: PFTranscripts.preamble,
        )
    }

    private func ruleResult(_ arguments: [String]) -> PFCommandResult {
        if arguments == ["-a", "com.apple/wgex", "-sr"] {
            return PFCommandResult(stdout: mismatch ? "pass quick all\n" : loaded, stderr: PFTranscripts.preamble)
        }
        if arguments == ["-a", "com.apple/wgex", "-vsr"] {
            return PFCommandResult(
                stdout: verbosePF(mismatch ? "pass quick all\n" : loaded, counter: UInt64(canary)),
                stderr: PFTranscripts.preamble,
            )
        }
        return PFCommandResult(stderr: PFTranscripts.preamble)
    }

    package func run(arguments: [String], input: Data, deadline: TimeInterval) throws -> PFCommandResult {
        calls.append(arguments)
        if let scripted = scriptedResult(arguments, input: input) {
            return scripted
        }
        if timeoutLoad, arguments.contains("-f"), !arguments.contains("-n") {
            timeoutLoad = false; throw DaemonFailure.pfDeadline
        }
        if arguments == ["-s", "References"] {
            return try referenceResult()
        }
        if arguments == ["-s", "info"] {
            return try PFCommandResult(stdout: PFTranscripts.enabledInfo(!disabled), stderr: PFTranscripts.preamble)
        }
        if arguments.first == "-X", failRelease {
            return PFCommandResult(status: 3, stderr: PFTranscripts.preamble)
        }
        if arguments == ["-E"] {
            return try PFCommandResult(stderr: PFTranscripts.read("enable", token: "99"))
        }
        if arguments == ["-s", "rules"] {
            return try PFCommandResult(stdout: missingStock ? "" : PFTranscripts.stdout("rules"), stderr: PFTranscripts.preamble)
        }
        if arguments == ["-a", "com.apple", "-s", "Anchors", "-v"] {
            return try PFCommandResult(stdout: PFTranscripts.stdout("anchors"), stderr: PFTranscripts.preamble)
        }
        if arguments == ["-o", "none", "-a", "com.apple/wgex", "-f", "-"] {
            journalWasWrittenBeforeLoad = journal.readToken() == "99"
            loaded = String(decoding: input, as: UTF8.self)
        }
        return ruleResult(arguments)
    }
}

/// The scripted kernel renders its stored constant table as pfctl's one-address-per-line output.
package func pfTableOutput(_ text: String) -> String {
    guard let declaration = text.split(separator: "\n").first(where: { $0.hasPrefix("table <wgex_") }),
          let start = declaration.firstIndex(of: "{"), let end = declaration.lastIndex(of: "}") else { return "" }
    return declaration[declaration.index(after: start) ..< end].split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: "\n") + "\n"
}
