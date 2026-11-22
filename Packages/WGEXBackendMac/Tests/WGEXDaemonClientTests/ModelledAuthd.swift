// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
// Shared with WGEXUITests through a symlink; keep it free of target-specific helpers.
#if os(macOS)
    import Foundation
    import Security
    import Synchronization
    @testable import WGEXDaemonProtocol

    /// The one read-back fixture: the WGEX right as authd returns it and its delegate. M03-T11 compares the
    /// same file with the definition macOS 27 returns.
    internal nonisolated enum AdminRightReadback {
        internal static let relativePath = "Packages/WGEXBackendMac/Tests/AdminRight/admin-right-readback.json"

        internal static func right() throws -> [String: Any] {
            try section("rightDefinition")
        }

        internal static func delegate() throws -> [String: Any] {
            try section("delegateDefinition")
        }

        private static func section(_ key: String) throws -> [String: Any] {
            var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            while directory.path != "/" {
                let candidate = directory.appendingPathComponent(relativePath)
                if FileManager.default.fileExists(atPath: candidate.path) {
                    let document = try JSONSerialization.jsonObject(with: Data(contentsOf: candidate)) as? [String: Any]
                    guard let value = document?[key] as? [String: Any] else { throw CocoaError(.fileReadCorruptFile) }
                    return value
                }
                directory.deleteLastPathComponent()
            }
            throw CocoaError(.fileNoSuchFile)
        }
    }

    /// Models authd as engine.m evaluates a default-mode reference. An approval in the app stores an admin
    /// credential on the app's token; the daemon's recheck happens a dispatch latency later and accepts that
    /// credential only while its age is within the evaluated user rule's timeout. Without extendRights no new
    /// credential is acquired.
    internal final nonisolated class ModelledAuthd: Sendable {
        /// Age of the app's credential when the daemon rechecks it (the guest logged 0.0099 seconds).
        internal static let dispatchLatency = 0.01

        private struct State {
            var database: [String: Data]
            var now = 1000.0
            var tokens: Set<UInt8> = []
            var credentials: [UInt8: Double] = [:]
            var nextToken: UInt8 = 1
            var recheckFlags: [AuthorizationFlags] = []
            var recheckNames: [String] = []
            var frees = 0
            var writes: [String] = []
        }

        private let state: Mutex<State>

        internal init(database: [String: [String: Any]]) throws {
            state = try Mutex(State(database: database.mapValues { try JSONSerialization.data(withJSONObject: $0) }))
        }

        /// The WGEX right and its delegate exactly as the read-back fixture models them.
        internal static func fixture() throws -> ModelledAuthd {
            try ModelledAuthd(database: [
                AuthorisationTable.adminRightName: AdminRightReadback.right(),
                AdminRightDefinition.delegateName: AdminRightReadback.delegate(),
            ])
        }

        internal func set(_ name: String, _ definition: [String: Any]?) throws {
            let data = try definition.map { try JSONSerialization.data(withJSONObject: $0) }
            state.withLock { $0.database[name] = data }
        }

        internal func definition(_ name: String) -> [String: Any]? {
            state.withLock { $0.database[name] }.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        }

        internal func advance(_ seconds: Double) {
            state.withLock { $0.now += seconds }
        }

        /// The user approves the app's prompt: the token gains an admin credential and is exported.
        internal func approve() -> Data {
            state.withLock { state in
                let token = Self.newToken(&state)
                state.credentials[token] = state.now
                return Self.form(token)
            }
        }

        /// An exported reference that never obtained a credential.
        internal func unapproved() -> Data {
            state.withLock { Self.form(Self.newToken(&$0)) }
        }

        internal var recheckFlags: [AuthorizationFlags] {
            state.withLock { $0.recheckFlags }
        }

        internal var recheckNames: [String] {
            state.withLock { $0.recheckNames }
        }

        internal var frees: Int {
            state.withLock { $0.frees }
        }

        internal var writes: [String] {
            state.withLock { $0.writes }
        }

        /// The daemon's Security calls for the recheck.
        internal var ports: DaemonAuthorisationPorts {
            DaemonAuthorisationPorts(importForm: { form, reference in
                let token = UInt8(bitPattern: form.pointee.bytes.0)
                guard form.pointee.bytes.1 == Self.marker, self.state.withLock({ $0.tokens.contains(token) }) else {
                    return errAuthorizationInvalidRef
                }
                reference.pointee = OpaquePointer(bitPattern: 0x1000 + Int(token))
                return errAuthorizationSuccess
            }, copy: { reference, rights, flags in
                let token = UInt8(Int(bitPattern: reference) - 0x1000)
                guard rights.pointee.count == 1, let item = rights.pointee.items?.pointee else { return errAuthorizationInvalidSet }
                let name = String(cString: item.name)
                return self.state.withLock { state in
                    state.now += Self.dispatchLatency
                    state.recheckFlags.append(flags); state.recheckNames.append(name)
                    return Self.evaluate(name, token: token, flags: flags, state: state, depth: 0)
                }
            }, free: { _ in
                self.state.withLock { $0.frees += 1 }
                return errAuthorizationSuccess
            })
        }

        /// The root daemon's database calls; a rule-class write keeps only the keys authd stores for that class.
        internal var database: AdminRightDatabasePorts {
            AdminRightDatabasePorts(read: { name in self.definition(name) }, write: { name, definition in
                var stored = definition
                if definition["class"] as? String == "rule" {
                    stored = definition.filter { ["class", "rule", "k-of-n", "comment"].contains($0.key) }
                    stored["version"] = 0; stored["created"] = 814_991_105.5; stored["modified"] = 815_724_327.9
                    stored["identifier"] = "com.magrathean.WGEXApp.dev.daemon"
                }
                guard let data = try? JSONSerialization.data(withJSONObject: stored) else { return false }
                self.state.withLock { $0.database[name] = data; $0.writes.append(name) }
                return true
            }, isRoot: { true })
        }

        /// Production policy and recheck over this model; the console check is not under test here.
        internal var authorisation: DaemonAuthorisation {
            let system = DaemonAuthorisation.makeSystem(policy: AdminRightPolicy.makeSystem(ports: database), ports: ports)
            return DaemonAuthorisation(isConsoleUser: { _ in true }, hasAdminRight: system.hasAdminRight)
        }

        private static let marker: CChar = 0x57

        private static func newToken(_ state: inout State) -> UInt8 {
            let token = state.nextToken
            state.nextToken += 1; state.tokens.insert(token)
            return token
        }

        private static func form(_ token: UInt8) -> Data {
            var bytes = Data(count: MemoryLayout<AuthorizationExternalForm>.size)
            bytes[0] = token; bytes[1] = UInt8(bitPattern: marker)
            return bytes
        }

        private static func evaluate(_ name: String, token: UInt8, flags: AuthorizationFlags, state: State, depth: Int) -> OSStatus {
            guard depth < 4, let data = state.database[name],
                  let rule = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return errAuthorizationDenied }
            switch rule["class"] as? String {
            case "allow":
                return errAuthorizationSuccess
            case "rule":
                let delegates = (rule["rule"] as? [String]) ?? (rule["rule"] as? String).map { [$0] } ?? []
                guard !delegates.isEmpty else { return errAuthorizationDenied }
                for delegate in delegates {
                    let status = evaluate(delegate, token: token, flags: flags, state: state, depth: depth + 1)
                    guard status == errAuthorizationSuccess else { return status }
                }
                return errAuthorizationSuccess
            case "user":
                return evaluateUser(rule, token: token, flags: flags, state: state)
            default:
                return errAuthorizationDenied
            }
        }

        /// A user rule accepts the token's credential while it is within the rule's timeout; a missing timeout
        /// never expires. Without extendRights no credential is acquired.
        private static func evaluateUser(_ rule: [String: Any], token: UInt8, flags: AuthorizationFlags, state: State) -> OSStatus {
            guard rule["group"] as? String == "admin" else { return errAuthorizationDenied }
            let timeout = (rule["timeout"] as? NSNumber)?.doubleValue ?? Double(Int32.max)
            if let created = state.credentials[token], state.now - created <= timeout {
                return errAuthorizationSuccess
            }
            guard flags.contains(.extendRights) else { return errAuthorizationDenied }
            if flags.contains(.preAuthorize), timeout == 0 {
                return errAuthorizationSuccess
            }
            return flags.contains(.interactionAllowed) ? errAuthorizationCanceled : errAuthorizationInteractionNotAllowed
        }
    }
#endif
