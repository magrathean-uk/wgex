// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import WGEXCore
    #if WGEX_LAB_BUILD
        import os
    #endif

    /// Production adapter. Initialisation is inert; only connect opens the system Mach service.
    /// Tests instantiate InMemoryXPCTransport exclusively.
    public actor NSXPCClientTransport: XPCTransport {
        private var connection: NSXPCConnection?
        private let proxyLookup: (@Sendable (@escaping (any Error) -> Void) -> (any WGEXDaemonXPC)?)?
        private var callbacks: XPCClientCallbacks?
        private var epoch = UUID()
        private let deadline: RequestDeadline
        private let requestSender: (@Sendable (Data, Data?, @escaping @Sendable (Result<Data, any Error>) -> Void) -> Void)?

        #if WGEX_LAB_BUILD
            private static let labLogger = Logger(subsystem: BuildIdentifiers.current.logSubsystem, category: "lab-code-identity")
            /// DEC-013: where the running daemon publishes its own code-directory hashes.
            private let labDaemonIdentity: LabDaemonIdentityFile
        #endif

        /// Release pins the daemon's designated requirement; Lab builds pin the hashes the running daemon published.
        public init() {
            deadline = RequestDeadline()
            requestSender = nil
            proxyLookup = nil
            #if WGEX_LAB_BUILD
                labDaemonIdentity = .production
            #endif
        }

        #if WGEX_LAB_BUILD
            /// Test seam: the published daemon identity at a temporary root. connect opens no connection unless it pins.
            package init(labDaemonIdentity: LabDaemonIdentityFile) {
                deadline = RequestDeadline()
                requestSender = nil
                proxyLookup = nil
                self.labDaemonIdentity = labDaemonIdentity
            }
        #endif

        /// In-memory adapter seam; construction and connect never open a Mach service.
        package init(
            clock: XPCClock,
            requestSender: @escaping @Sendable (Data, Data?, @escaping @Sendable (Result<Data, any Error>) -> Void) -> Void,
        ) {
            deadline = RequestDeadline(clock: clock)
            self.requestSender = requestSender
            proxyLookup = nil
            #if WGEX_LAB_BUILD
                labDaemonIdentity = .production
            #endif
        }

        /// Exercises the Foundation-style, unannotated proxy-error callback without opening XPC.
        package init(proxyLookup: @escaping @Sendable (@escaping (any Error) -> Void) -> (any WGEXDaemonXPC)?) {
            self.proxyLookup = proxyLookup
            deadline = RequestDeadline(); requestSender = nil
            #if WGEX_LAB_BUILD
                labDaemonIdentity = .production
            #endif
        }

        public func connect(callbacks: XPCClientCallbacks) throws {
            connection?.invalidate()
            self.callbacks = callbacks
            epoch = UUID()
            let attempt = epoch
            if requestSender != nil || proxyLookup != nil {
                return
            }
            #if WGEX_LAB_BUILD
                // DEC-013: pin the hashes the running daemon published; never this bundle's daemon, never unpinned.
                let requirement: String
                do { requirement = try LabDaemonPin.requirement(file: labDaemonIdentity) }
                catch {
                    connection = nil
                    Self.labLogger.error("Lab daemon connection refused: the published daemon identity is missing, unsafe or malformed")
                    throw error
                }
            #endif
            let next = NSXPCConnection(machServiceName: BuildIdentifiers.daemonService, options: .privileged)
            #if WGEX_LAB_BUILD
                next.setCodeSigningRequirement(requirement)
            #else
                next.setCodeSigningRequirement(RequirementStrings.current.daemonRequirement)
            #endif
            next.remoteObjectInterface = NSXPCInterface(with: (any WGEXDaemonXPC).self)
            next.exportedInterface = NSXPCInterface(with: (any WGEXClientEventsXPC).self)
            next.exportedObject = ClientEventsExport(callbacks: callbacks)
            next.interruptionHandler = interruptionHandler(attempt)
            next.invalidationHandler = interruptionHandler(attempt)
            connection = next
            next.resume()
        }

        public func send(_ envelope: Data, secrets: Data?) async throws -> Data {
            let request = try Envelope.decode(envelope).body
            let attempt = epoch
            if let requestSender {
                return try await deadline.wait(
                    for: request,
                    isolation: self,
                    begin: { requestSender(envelope, secrets, $0) },
                    interrupted: { await self.interrupted(attempt) },
                )
            }
            guard connection != nil || proxyLookup != nil else { throw DaemonError.disconnected }
            return try await deadline.wait(for: request, isolation: self, begin: { finish in
                let onError = proxyErrorHandler(finish: finish, attempt: attempt)
                guard let proxy = proxyLookup?(onError) ?? (connection?.remoteObjectProxyWithErrorHandler(onError) as? any WGEXDaemonXPC)
                else {
                    finish(.failure(DaemonError.disconnected))
                    Task { await self.interrupted(attempt) }
                    return
                }
                let reply: @Sendable (Data) -> Void = { finish(.success($0)) }
                switch request {
                case .startIntent, .startCutover: proxy.start(envelope, secrets: secrets ?? Data(), reply: reply)
                case .setStartBeforeLoginIntent: proxy.setStartBeforeLogin(envelope, secrets: secrets ?? Data(), reply: reply)
                case .subscribeEvents: proxy.subscribe(envelope, reply: reply)
                case .armOnDemand: proxy.armOnDemand(envelope, secrets: secrets ?? Data(), reply: reply)
                default: proxy.send(envelope, reply: reply)
                }
            }, interrupted: { await self.interrupted(attempt) })
        }

        private nonisolated func interruptionHandler(_ attempt: UUID) -> @Sendable () -> Void {
            { Task { await self.interrupted(attempt) } }
        }

        private nonisolated func proxyErrorHandler(
            finish: @escaping @Sendable (Result<Data, any Error>) -> Void, attempt: UUID,
        ) -> @Sendable (any Error) -> Void {
            { error in
                #if WGEX_LAB_BUILD
                    let error = error as NSError
                    if error.domain == NSCocoaErrorDomain, error.code == NSXPCConnectionCodeSigningRequirementFailure {
                        Self.labLogger.error("Lab daemon connection refused: the running daemon does not match its published identity")
                    }
                #endif
                finish(.failure(DaemonError.disconnected))
                Task { await self.interrupted(attempt) }
            }
        }

        private func interrupted(_ attempt: UUID) async {
            guard attempt == epoch else { return }
            let callback = callbacks
            invalidate()
            await callback?.invalidated()
        }

        public func invalidate() {
            epoch = UUID()
            callbacks = nil
            connection?.invalidationHandler = nil
            connection?.interruptionHandler = nil
            connection?.invalidate()
            connection = nil
        }
    }

#endif
