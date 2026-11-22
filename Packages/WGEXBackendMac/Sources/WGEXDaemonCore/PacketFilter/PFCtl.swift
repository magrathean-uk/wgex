// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol

public protocol PFTokenJournalling: Sendable {
    /// Complete durable ownership and write-ahead state.
    func readState() throws -> PFTokenState
    /// Atomically replaces ownership and pending enable state.
    func writeState(_ state: PFTokenState) throws
    func readToken() throws -> String?
    /// Must be durable before returning. Failure prevents every rule load.
    func writeToken(_ token: String?) throws
}

/// Serialised by PolicyEnforcer; owns no global PF state.
public struct PFCtl: Sendable {
    public enum StateKill: Sendable {
        case interface(PFInterface)
        /// Explicit local hosts only; never an implicit 0/0 kill. VM fallback, not auto-selected.
        case hosts(interface: PFInterface, addresses: [PFAddress])

        public var arguments: [[String]] {
            switch self {
            case let .interface(interface): [["-i", interface.name, "-F", "states"]]
            case let .hosts(interface, addresses):
                Array(Set(addresses)).sorted().flatMap { address in
                    [
                        ["-i", interface.name, "-k", address.text],
                        ["-i", interface.name, "-k", address.isIPv6 ? "::/0" : "0.0.0.0/0", "-k", address.text],
                    ]
                }
            }
        }
    }

    public let system: any PacketFilterSystem
    public let deadline: TimeInterval
    public init(system: any PacketFilterSystem, deadline: TimeInterval = 10) {
        self.system = system; self.deadline = deadline
    }

    @discardableResult
    package func command(_ arguments: [String], input: String = "") async throws -> PFCommandResult {
        let result = try await system.run(arguments: arguments, input: Data(input.utf8), deadline: deadline)
        guard result.status == 0 else {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.packetFilterFailure(status: result.status, stderr: result.stderr)
            #endif
            if arguments.contains("-f") {
                throw DaemonFailure.pfVerification
            }
            throw DaemonFailure.pfProcess(result.status)
        }
        return result
    }

    public func enable(beforeExec: @escaping @Sendable (Int32) throws -> Void = { _ in }) async throws -> String {
        let result = try await system.enable(deadline: deadline, beforeExec: beforeExec)
        guard result.status == 0 else { throw DaemonFailure.pfProcess(result.status) }
        return try PacketFilterReadback.token(result.stderr + "\n" + result.stdout)
    }

    public func release(token: String) async throws {
        guard PacketFilterReadback.validToken(token) else { throw DaemonFailure.pfToken }
        try await command(["-X", token])
    }

    public func references() async throws -> String {
        try await command(["-s", "References"]).stdout
    }

    public func isEnabled() async throws -> Bool {
        let result = try await command(["-s", "info"])
        return result.stdout.split(separator: "\n").contains { line in
            let words = line.split(whereSeparator: \.isWhitespace)
            return words.count >= 2 && words[0] == "Status:" && words[1] == "Enabled"
        }
    }

    /// Stdin avoids a privileged temporary file and a path replacement race. The ruleset optimiser
    /// is off: on macOS 26 its default "basic" level drops rules it considers subsets (DHCP,
    /// DHCPv6) and reorders quick rules, so the read-back never matched the rendered text
    /// (lab guest, 26 Oct 2026); the rendered order is the security property being verified.
    public func load(_ text: String) async throws {
        try await command(["-o", "none", "-n", "-a", PacketFilterRenderer.anchor, "-f", "-"], input: text)
        try await command(["-o", "none", "-a", PacketFilterRenderer.anchor, "-f", "-"], input: text)
        let readback = try await command(["-a", PacketFilterRenderer.anchor, "-sr"])
        guard PacketFilterReadback.matches(readback.stdout, rendered: text) else {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(DaemonFailure.pfVerification, context: "pf load readback")
            #endif
            #if WGEX_LAB_BUILD
                // Lab only: both rule texts (addresses, never secrets) for diffing on the guest.
                try? text.write(toFile: "/private/tmp/wgex-lab-pf-rendered.txt", atomically: true, encoding: .utf8)
                try? readback.stdout.write(toFile: "/private/tmp/wgex-lab-pf-readback.txt", atomically: true, encoding: .utf8)
            #endif
            throw DaemonFailure.pfVerification
        }
    }

    /// A table name binds the text, while this read proves the kernel contains exactly those ranges.
    package func verifyTunnelTable(_ context: PFContext) async throws {
        guard !context.tunnelRanges.isEmpty else { return }
        let result = try await command(["-a", PacketFilterRenderer.anchor, "-t", PacketFilterRenderer.tunnelTable(context), "-T", "show"])
        let actual = try result.stdout.split(whereSeparator: \.isWhitespace).map { try WGEXCore.IPAddressRange(String($0)).network }
        guard Set(actual) == Set(context.tunnelRanges), actual.count == context.tunnelRanges.count else {
            throw DaemonFailure.pfVerification
        }
    }

    public func killStates(_ strategy: StateKill) async throws {
        for arguments in strategy.arguments {
            try await command(arguments)
        }
    }

    public func canaryEvaluations() async throws -> UInt64 {
        try await PacketFilterReadback.canaryEvaluations(command(["-a", PacketFilterRenderer.anchor, "-vsr"]).stdout)
    }
}
