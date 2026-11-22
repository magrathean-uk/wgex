// SPDX-License-Identifier: MIT
import os
import WGEXCore
import WGEXDaemonProtocol

/// Registration progress during replacement of a compatible older daemon.
public enum UpdateHandoffState: Sendable, Equatable {
    /// The daemon acknowledged preparation; registration is being replaced.
    case finishing
    /// System Settings must approve the replacement service.
    case needsApproval
    /// Registration is enabled; a fresh hello must confirm the replacement build.
    case ready
}

/// Bounds on the registration steps of the update hand-off.
public struct UpdateHandoffLimits: Sendable, Equatable {
    /// How long the unregister step may take before registration goes ahead anyway.
    public var unregister: Duration
    /// How long register plus the wait for enabled or requires-approval may take.
    public var registration: Duration
    /// Interval between status reads while unregister has not returned or the bootout has not finished.
    public var statusPoll: Duration
    /// How long to wait, after unregister returned, for the status to show the daemon gone before registering.
    public var bootout: Duration
    /// Register tries in total; a system failure is retried until this many tries have failed.
    public var registerAttempts: Int
    /// Pause between a failed register and the next try.
    public var registerRetryPause: Duration

    /// Creates a set of bounds.
    public init(
        unregister: Duration, registration: Duration, statusPoll: Duration, bootout: Duration = .seconds(10),
        registerAttempts: Int = 3, registerRetryPause: Duration = .seconds(2),
    ) {
        self.unregister = unregister
        self.registration = registration
        self.statusPoll = statusPoll
        self.bootout = bootout
        self.registerAttempts = max(1, registerAttempts)
        self.registerRetryPause = registerRetryPause
    }

    /// Production bounds.
    public static let standard = UpdateHandoffLimits(
        unregister: .seconds(10), registration: .seconds(30), statusPoll: .milliseconds(250),
    )

    /// The registration bound plus the pauses between register tries.
    fileprivate var registrationWithRetries: Duration {
        registration + registerRetryPause * (registerAttempts - 1)
    }
}

/// The NSError behind a failed system call, kept because ``ServiceError`` carries only the code.
public struct SystemErrorIdentity: Sendable, Equatable {
    /// NSError domain.
    public var domain: String
    /// NSError code.
    public var code: Int

    /// Creates an identity.
    public init(domain: String, code: Int) {
        self.domain = domain
        self.code = code
    }
}

/// Synchronous registration details the hand-off reads between steps; ``ServiceController`` conforms.
/// A service without them registers right after unregister returns and logs no NSError domain.
public protocol ServiceStatusReporting: Sendable {
    /// The registration status now, read without subscribing to ``ServiceControlling/state``.
    var currentStatus: ServiceState { get }
    /// Domain and code of the most recent failed system register, or nil when none failed.
    var lastRegisterFailure: SystemErrorIdentity? { get }
}

/// Update orchestration contains no signing or direct ServiceManagement calls.
public enum DaemonUpdateHandoff {
    private static let logger = Logger(subsystem: BuildIdentifiers.current.logSubsystem, category: "update")

    private enum UnregisterEvent: Sendable {
        case returned, failed(ServiceError), status(ServiceState), timedOut
    }

    /// Why the unregister step let registration go ahead.
    private enum UnregisterOutcome: Sendable {
        case returned, gone, timedOut
    }

    private enum RegisterEvent: Sendable {
        case failed(ServiceError), state(ServiceState), ended, timedOut
    }

    /// Prepares the older daemon before re-registering; approval remains an explicit user action.
    /// Unregister is bounded because macOS may boot the daemon out without ever calling back.
    public static func run(
        client: DaemonClient, service: any ServiceControlling, currentBuild: Int,
        grant: any SecureInstallGrant, limits: UpdateHandoffLimits = .standard,
        changed: @escaping @Sendable (UpdateHandoffState) async -> Void,
    ) async throws {
        defer { withExtendedLifetime(grant) {} }
        let hello = try await client.connect()
        guard hello.daemonBuild < currentBuild else { return }
        await changed(.finishing)
        logger.log("update hand-off: preparing daemon build \(hello.daemonBuild, privacy: .public)")
        let reply = try await client.request(.prepareForUpdate, authorization: grant.externalForm)
        guard case .ok = reply else { throw DaemonError.malformedMessage }
        await client.disconnect()
        if try await unregister(service, limits: limits) == .returned {
            // Unregister can return before launchd has booted the daemon out; registering then fails (M5.3-07).
            try await awaitBootout(service, limits: limits)
        }
        try await register(service, limits: limits, changed: changed)
    }

    /// Ends when unregister returns, or a status read shows the daemon is gone, or the bound expires.
    private static func unregister(
        _ service: any ServiceControlling, limits: UpdateHandoffLimits,
    ) async throws -> UnregisterOutcome {
        logger.log("update hand-off: unregistering")
        let (events, sink) = AsyncStream<UnregisterEvent>.makeStream()
        let tasks = [
            Task {
                do throws(ServiceError) {
                    try await service.unregister()
                    sink.yield(.returned)
                } catch {
                    sink.yield(.failed(error))
                }
            },
            Task {
                while await (try? Task.sleep(for: limits.statusPoll)) != nil {
                    if let state = await currentState(service) {
                        sink.yield(.status(state))
                    }
                }
            },
            Task {
                if await (try? Task.sleep(for: limits.unregister)) != nil {
                    sink.yield(.timedOut)
                }
            },
        ]
        defer {
            tasks.forEach { $0.cancel() }
            sink.finish()
        }
        var failure: ServiceError?
        for await event in events {
            if let outcome = try unregisterFinished(event, failure: &failure) {
                return outcome
            }
        }
        try Task.checkCancellation()
        throw DaemonError.disconnected
    }

    /// Set once registration may proceed; throws a recorded unregister failure the status does not excuse.
    private static func unregisterFinished(
        _ event: UnregisterEvent, failure: inout ServiceError?,
    ) throws -> UnregisterOutcome? {
        switch event {
        case .returned:
            logger.log("update hand-off: unregister returned")
            return .returned
        case .status(.notRegistered), .status(.notFound):
            logger.log("update hand-off: status shows the daemon unregistered")
            return .gone
        case .status:
            if let failure {
                throw failure
            }
            return nil
        case let .failed(error):
            logger.error("update hand-off: unregister failed: \(String(describing: error), privacy: .public)")
            failure = error
            return nil
        case .timedOut:
            if let failure {
                throw failure
            }
            logger.error("update hand-off: unregister did not complete in time; registering anyway")
            return .timedOut
        }
    }

    /// Waits until the status shows the daemon unregistered or not found, or the bootout bound expires.
    private static func awaitBootout(_ service: any ServiceControlling, limits: UpdateHandoffLimits) async throws {
        guard let reporter = service as? any ServiceStatusReporting else {
            logger.log("update hand-off: no synchronous status; registering without the bootout wait")
            return
        }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: limits.bootout)
        var waited = false
        while true {
            let state = reporter.currentStatus
            if state == .notRegistered || state == .notFound {
                if waited {
                    logger.log("update hand-off: status shows the bootout finished")
                }
                return
            }
            guard clock.now < deadline else {
                logger.error("update hand-off: status still registered after the bootout bound; registering anyway")
                return
            }
            if !waited {
                waited = true
                logger.log("update hand-off: waiting for the bootout, status \(String(describing: state), privacy: .public)")
            }
            try await Task.sleep(for: min(limits.statusPoll, deadline - clock.now))
        }
    }

    /// Registers, then waits a bounded time for enabled or requires-approval; approval itself is unbounded.
    private static func register(
        _ service: any ServiceControlling, limits: UpdateHandoffLimits,
        changed: @escaping @Sendable (UpdateHandoffState) async -> Void,
    ) async throws {
        logger.log("update hand-off: registering")
        let (events, sink) = AsyncStream<RegisterEvent>.makeStream()
        let registration = Task {
            do throws(ServiceError) {
                try await registerWithRetry(service, limits: limits)
            } catch {
                sink.yield(.failed(error))
                return
            }
            for await state in service.state {
                sink.yield(.state(state))
            }
            sink.yield(.ended)
        }
        let timer = Task {
            if await (try? Task.sleep(for: limits.registrationWithRetries)) != nil {
                sink.yield(.timedOut)
            }
        }
        defer {
            registration.cancel()
            timer.cancel()
            sink.finish()
        }
        var awaitingApproval = false
        for await event in events {
            switch try registrationStep(event, awaitingApproval: awaitingApproval) {
            case .ready:
                await changed(.ready)
                return
            case .needsApproval:
                awaitingApproval = true
                timer.cancel()
                await changed(.needsApproval)
            case .finishing:
                await changed(.finishing)
            case nil:
                continue
            }
        }
        try Task.checkCancellation()
        throw DaemonError.disconnected
    }

    /// Retries a system register failure after a pause, up to the bound; host-guard and unsupported fail at once.
    private static func registerWithRetry(
        _ service: any ServiceControlling, limits: UpdateHandoffLimits,
    ) async throws(ServiceError) {
        var attempt = 1
        while true {
            do throws(ServiceError) {
                try await service.register()
                if attempt > 1 {
                    logger.log("update hand-off: register succeeded on try \(attempt, privacy: .public)")
                }
                return
            } catch {
                logRegisterFailure(error, service: service, attempt: attempt, of: limits.registerAttempts)
                guard case .system = error, attempt < limits.registerAttempts,
                      await (try? Task.sleep(for: limits.registerRetryPause)) != nil
                else { throw error }
            }
            attempt += 1
        }
    }

    private static func logRegisterFailure(
        _ error: ServiceError, service: any ServiceControlling, attempt: Int, of attempts: Int,
    ) {
        // Only a system failure has an NSError behind it; a stale identity must not label a guard refusal.
        var identity: SystemErrorIdentity?
        if case .system = error {
            identity = (service as? any ServiceStatusReporting)?.lastRegisterFailure
        }
        let domain = identity?.domain ?? "unknown"
        let code = identity.map { String($0.code) } ?? "unknown"
        let detail = "try \(attempt) of \(attempts) failed: \(error) domain \(domain) code \(code)"
        logger.error("update hand-off: register \(detail, privacy: .public)")
    }

    /// Maps a registration event to the state to report, or throws when the hand-off failed.
    private static func registrationStep(_ event: RegisterEvent, awaitingApproval: Bool) throws -> UpdateHandoffState? {
        switch event {
        case let .failed(error):
            logger.error("update hand-off: register failed: \(String(describing: error), privacy: .public)")
            throw error
        case .state(.enabled):
            logger.log("update hand-off: registration enabled")
            return .ready
        case .state(.requiresApproval):
            logger.log("update hand-off: registration requires approval")
            return .needsApproval
        case .state:
            return .finishing
        case .ended:
            logger.error("update hand-off: registration state stream ended")
            throw DaemonError.disconnected
        case .timedOut where awaitingApproval:
            return nil
        case .timedOut:
            logger.error("update hand-off: registration not enabled or awaiting approval in time")
            throw DaemonError.disconnected
        }
    }

    /// The first element of a fresh subscription is the current state.
    private static func currentState(_ service: any ServiceControlling) async -> ServiceState? {
        for await state in service.state {
            return state
        }
        return nil
    }
}
