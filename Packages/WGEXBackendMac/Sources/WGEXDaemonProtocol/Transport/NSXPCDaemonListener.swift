// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Synchronization
    import WGEXCore

    /// The listener is created and resumed only by an explicit start() in the daemon.
    /// Immutable policy and a mutex-protected listener are the sendability invariant.
    public final class NSXPCDaemonListener: NSObject, NSXPCListenerDelegate, Sendable {
        private let afterUpdateReply: @Sendable () -> Void
        private let daemon: any XPCDaemonTransport
        private let listener = Mutex<NSXPCListener?>(nil)

        private let codeIdentity: any CodeIdentityReading
        private let executableURL: URL
        #if !WGEX_LAB_BUILD
            private let peerRequirement = Mutex<String?>(nil)
        #endif

        public init(
            daemon: any XPCDaemonTransport,
            afterUpdateReply: @escaping @Sendable () -> Void = {},
            codeIdentity: any CodeIdentityReading = CodeIdentity(),
            executableURL: URL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]),
        ) {
            self.afterUpdateReply = afterUpdateReply
            self.daemon = daemon
            self.codeIdentity = codeIdentity
            self.executableURL = executableURL
        }

        public func start() {
            listener.withLock { listener in
                guard listener == nil else { return }
                let next = NSXPCListener(machServiceName: BuildIdentifiers.daemonService)
                #if !WGEX_LAB_BUILD
                    let requirement = RequirementStrings.current.clientRequirement
                    peerRequirement.withLock { $0 = requirement }
                    next.setConnectionCodeSigningRequirement(requirement)
                #endif
                // Lab builds (DEC-013) pin nothing here: the delegate measures the installed app and CLI per connection.
                next.delegate = self
                listener = next
                next.resume()
            }
        }

        public func invalidate() {
            listener.withLock { listener in
                listener?.invalidate()
                listener = nil
            }
        }

        public func listener(_: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            let auditToken = Self.auditToken(of: connection)
            #if WGEX_LAB_BUILD
                // The code behind the audit token must match the installed app or CLI as measured now.
                guard let requirement = LabClientAdmission(reader: codeIdentity).requirement(auditToken: auditToken) else {
                    return false
                }
            #else
                guard let requirement = peerRequirement.withLock({ $0 }) else { return false }
            #endif
            connection.setCodeSigningRequirement(requirement)
            // Foundation has already enforced the listener requirement before this delegate (Lab: the check above).
            let peer = VerifiedPeerIdentity(
                uid: connection.effectiveUserIdentifier, pid: connection.processIdentifier,
                auditSessionID: UInt32(bitPattern: connection.auditSessionIdentifier), codeSigningVerdict: .requirementSatisfied,
                auditToken: auditToken,
            )
            connection.remoteObjectInterface = NSXPCInterface(with: (any WGEXClientEventsXPC).self)
            let callbacks = Self.callbacks(connection)
            let daemon = daemon
            let accepted = Task { try await daemon.accept(peer: peer, callbacks: callbacks) }
            connection.exportedInterface = NSXPCInterface(with: (any WGEXDaemonXPC).self)
            connection.exportedObject = DaemonExport(
                daemon: daemon,
                accepted: accepted,
                afterUpdateReply: afterUpdateReply,
                connection: XPCConnectionBox(connection),
            )
            connection.invalidationHandler = {
                Task {
                    if let id = try? await accepted.value {
                        await daemon.disconnect(connectionID: id)
                    }
                }
            }
            connection.resume()
            return true
        }

        /// The connection's kernel audit token as `audit_token_t` bytes. Foundation exposes it only through key-value coding;
        /// a connection without it yields nil, which the daemon treats as "not the app".
        package static func auditToken(of connection: NSXPCConnection) -> Data? {
            let key = "auditToken"
            guard connection.responds(to: NSSelectorFromString(key)),
                  let value = connection.value(forKey: key) as? NSValue else { return nil }
            var token = audit_token_t()
            value.getValue(&token, size: MemoryLayout<audit_token_t>.size)
            return withUnsafeBytes(of: token) { Data($0) }
        }

        private static func callbacks(_ connection: NSXPCConnection) -> XPCClientCallbacks {
            let proxyConnection = XPCConnectionBox(connection)
            return XPCClientCallbacks(
                event: { bytes in
                    // Await the local XPC send barrier, keeping one send in flight per
                    // dispatcher subscriber. The interface has no remote receipt ack.
                    let _: Data? = try? await withCheckedThrowingContinuation { continuation in
                        let once = XPCReplyOnce(continuation)
                        guard let proxy = proxyConnection.connection.remoteObjectProxyWithErrorHandler({ _ in
                            once.finish(.failure(DaemonError.disconnected))
                            proxyConnection.connection.invalidate()
                        }) as? any WGEXClientEventsXPC else {
                            once.finish(.failure(DaemonError.disconnected))
                            return
                        }
                        proxy.event(bytes)
                        proxyConnection.connection.scheduleSendBarrierBlock { once.finish(.success(Data())) }
                    }
                },
                provideSecrets: Self.secretsCallback(proxy: { handler in
                    proxyConnection.connection.remoteObjectProxyWithErrorHandler(handler) as? any WGEXClientEventsXPC
                }),
            )
        }

        package static func encodeSecretsRequest(_ id: UUID) throws -> Data {
            try WireCodec.encode(SecretsRequest(profileID: id))
        }

        /// Shared with host tests; production supplies the authenticated connection's proxy.
        package static func secretsCallback(
            proxy: @escaping @Sendable (@escaping @Sendable (any Error) -> Void) -> (any WGEXClientEventsXPC)?,
            clock: XPCClock = .continuous,
        ) -> @Sendable (UUID) async throws -> Data {
            { id in
                do {
                    let bytes = try encodeSecretsRequest(id)
                    let response = try await RequestDeadline(clock: clock).wait(
                        for: .status, budget: SecretsCallback.budget, timeoutError: .tunnel(.timedOut),
                        discardLateReply: SecretsWireLayout.wipeReceived,
                        begin: { finish in
                            guard let remote = proxy({ _ in finish(.failure(DaemonError.disconnected)) }) else {
                                finish(.failure(DaemonError.disconnected)); return
                            }
                            remote.provideSecrets(bytes) { finish(.success($0)) }
                        }, interrupted: {},
                    )
                    return try SecretsCallback.response(response)
                } catch { throw SecretsCallback.failure(error) }
            }
        }
    }

    /// NSXPCConnection supports proxy lookup/invalidation from any queue. Configuration
    /// is complete before this immutable box escapes. Remove when Foundation annotates Sendable.
    private final class XPCConnectionBox: @unchecked Sendable {
        let connection: NSXPCConnection
        init(_ connection: NSXPCConnection) {
            self.connection = connection
        }
    }

    private final class DaemonExport: NSObject, WGEXDaemonXPC, Sendable {
        private let daemon: any XPCDaemonTransport
        private let accepted: Task<UUID, any Error>
        private let afterUpdateReply: @Sendable () -> Void
        private let connection: XPCConnectionBox

        init(
            daemon: any XPCDaemonTransport,
            accepted: Task<UUID, any Error>,
            afterUpdateReply: @escaping @Sendable () -> Void,
            connection: XPCConnectionBox,
        ) {
            self.afterUpdateReply = afterUpdateReply
            self.connection = connection
            self.daemon = daemon
            self.accepted = accepted
        }

        func send(_ envelope: Data, reply: @escaping @Sendable (Data) -> Void) {
            receive(envelope, secrets: nil, kind: .send, reply: reply)
        }

        func start(_ envelope: Data, secrets: Data, reply: @escaping @Sendable (Data) -> Void) {
            receive(envelope, secrets: secrets, kind: .start, reply: reply)
        }

        func setStartBeforeLogin(_ envelope: Data, secrets: Data, reply: @escaping @Sendable (Data) -> Void) {
            receive(envelope, secrets: secrets, kind: .login, reply: reply)
        }

        func subscribe(_ envelope: Data, reply: @escaping @Sendable (Data) -> Void) {
            receive(envelope, secrets: nil, kind: .subscribe, reply: reply)
        }

        func armOnDemand(_ envelope: Data, secrets: Data, reply: @escaping @Sendable (Data) -> Void) {
            receive(envelope, secrets: secrets, kind: .arm, reply: reply)
        }

        private enum Method: Sendable { case send, start, login, subscribe, arm }

        private func receive(_ envelope: Data, secrets: Data?, kind: Method, reply: @escaping @Sendable (Data) -> Void) {
            Task {
                // Prevent bypassing the separate-argument method contract.
                guard let body = try? Envelope.decode(envelope).body, Self.matches(body, method: kind),
                      let id = try? await accepted.value
                else {
                    reply((try? WireCodec.encode(Reply.error(.malformedMessage))) ?? Data())
                    return
                }
                let bytes = await daemon.receive(connectionID: id, envelope: envelope, secrets: secrets)
                reply(bytes)
                if case .prepareForUpdate = body, (try? WireCodec.decode(Reply.self, from: bytes)) == .ok {
                    connection.connection.scheduleSendBarrierBlock(afterUpdateReply)
                }
            }
        }

        private static func matches(_ request: Request, method: Method) -> Bool {
            switch request {
            case .startIntent, .startCutover: method == .start
            case .setStartBeforeLoginIntent: method == .login
            case .subscribeEvents: method == .subscribe
            case .armOnDemand: method == .arm
            default: method == .send
            }
        }
    }
#endif
