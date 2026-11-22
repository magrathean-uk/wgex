// SPDX-License-Identifier: MIT
#if os(macOS)
    import Darwin
    import Foundation
    import Security
    import Synchronization
    import Testing
    @testable import WGEXDaemonProtocol

    @objc private protocol AuditTokenProbeXPC {
        func ping(_ reply: @escaping @Sendable () -> Void)
    }

    private final class AuditTokenProbe: NSObject, AuditTokenProbeXPC, Sendable {
        func ping(_ reply: @escaping @Sendable () -> Void) {
            reply()
        }
    }

    /// Captures what the production extraction reads from each accepted connection.
    private final class AuditTokenListenerDelegate: NSObject, NSXPCListenerDelegate, Sendable {
        let captured = Mutex<Data?>(nil)

        func listener(_: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            let token = NSXPCDaemonListener.auditToken(of: connection)
            captured.withLock { $0 = token }
            connection.exportedInterface = NSXPCInterface(with: (any AuditTokenProbeXPC).self)
            connection.exportedObject = AuditTokenProbe()
            connection.resume()
            return true
        }
    }

    /// M02-T02: the daemon takes the peer's code identity (app versus CLI) from the XPC connection's audit token, never
    /// from a process-ID lookup, so a reused PID cannot pass as the app.
    @Suite(.timeLimit(.minutes(1)))
    private struct AuditTokenIdentityTests {
        static func ownToken() throws -> audit_token_t {
            var token = audit_token_t()
            var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
            let result = withUnsafeMutablePointer(to: &token) { pointer in
                pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                    task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
                }
            }
            try #require(result == KERN_SUCCESS)
            return token
        }

        static func bytes(_ token: audit_token_t) -> Data {
            withUnsafeBytes(of: token) { Data($0) }
        }

        @Test
        func `the connection's audit token locates the peer's code and the requirement decides`() throws {
            let token = try Self.bytes(Self.ownToken())
            #expect(DaemonAuthorisation.isAppProcess(auditToken: token, requirement: "always"))
            #expect(!DaemonAuthorisation.isAppProcess(auditToken: token, requirement: "never"))
        }

        @Test
        func `a token whose PID was reused by another process does not match`() throws {
            var reused = try Self.ownToken()
            reused.val.7 &+= 1 // Same PID, a later process ID version: what a recycled PID looks like.
            #expect(!DaemonAuthorisation.isAppProcess(auditToken: Self.bytes(reused), requirement: "always"))
            var other = try Self.ownToken()
            other.val.5 = 1 // Another live process's PID under this token's version.
            #expect(!DaemonAuthorisation.isAppProcess(auditToken: Self.bytes(other), requirement: "always"))
        }

        @Test
        func `the guest lookup uses only the audit token attribute, never the PID`() throws {
            let token = try Self.bytes(Self.ownToken())
            let keys = Mutex<[String]>([])
            _ = DaemonAuthorisation.isAppProcess(auditToken: token, requirement: "always") { attributes in
                let dictionary = attributes as NSDictionary
                keys.withLock { $0 = dictionary.allKeys.compactMap { $0 as? String } }
                #expect(dictionary[kSecGuestAttributeAudit] as? Data == token)
                return nil
            }
            #expect(keys.withLock { $0 } == [kSecGuestAttributeAudit as String])
        }

        @Test
        func `a missing or malformed token is never the app, even for a live PID`() {
            let called = Mutex(false)
            let guest: (CFDictionary) -> SecCode? = { _ in called.withLock { $0 = true }; return nil }
            #expect(!DaemonAuthorisation.isAppProcess(auditToken: nil, requirement: "always", guest: guest))
            #expect(!DaemonAuthorisation.isAppProcess(auditToken: Data(count: 31), requirement: "always", guest: guest))
            #expect(!called.withLock { $0 })
            let peer = VerifiedPeerIdentity(uid: getuid(), pid: getpid(), auditSessionID: 0, codeSigningVerdict: .requirementSatisfied)
            #expect(peer.auditToken == nil)
            #expect(!DaemonAuthorisation.isAppProcess(auditToken: peer.auditToken, requirement: "always"))
        }

        @Test
        func `the listener reads the accepted connection's audit token`() async throws {
            let delegate = AuditTokenListenerDelegate()
            let listener = NSXPCListener.anonymous()
            listener.delegate = delegate
            listener.resume()
            defer { listener.invalidate() }
            let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
            connection.remoteObjectInterface = NSXPCInterface(with: (any AuditTokenProbeXPC).self)
            connection.resume()
            defer { connection.invalidate() }
            let answered = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                let once = Mutex(false)
                let finish: @Sendable (Bool) -> Void = { value in
                    guard once.withLock({ done in defer { done = true }; return !done }) else { return }
                    continuation.resume(returning: value)
                }
                guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in finish(false) }) as? any AuditTokenProbeXPC else {
                    finish(false); return
                }
                proxy.ping { finish(true) }
            }
            try #require(answered)
            let captured = try #require(delegate.captured.withLock { $0 })
            #expect(try captured == Self.bytes(Self.ownToken()))
            #expect(DaemonAuthorisation.isAppProcess(auditToken: captured, requirement: "always"))
        }
    }
#endif
