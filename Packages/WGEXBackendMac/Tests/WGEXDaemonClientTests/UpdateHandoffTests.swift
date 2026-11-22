// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct UpdateHandoffTests {
    @Test
    func `compatible older daemon admits preparation before registration and approval`() async throws {
        let transport = ScriptedStatusTransport(daemonBuild: 9)
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10, minimumDaemonBuild: 1)
        _ = try await client.connect()
        let states = Mutex<[UpdateHandoffState]>([])
        let service = BootoutService(register: .stay(.requiresApproval))
        let handoff = Task {
            try await DaemonUpdateHandoff.run(
                client: client,
                service: service,
                currentBuild: 10,
                grant: Data([1]),
                changed: { value in states.withLock { $0.append(value) } },
            )
        }
        while !states.withLock({ $0.contains(.needsApproval) }) {
            await Task.yield()
        }
        #expect(await transport.requests.contains(.prepareForUpdate))
        #expect(await transport.preparationHadGrant)
        #expect(service.calls == ["unregister", "register"])
        #expect(states.withLock { $0.first } == .finishing)
        service.transition(to: .enabled)
        try await handoff.value
        #expect(states.withLock { $0.last } == .ready)
        await client.disconnect()
    }

    @Test
    func `preparation failure after progress keeps the real client connected and never registers`() async throws {
        let transport = ScriptedStatusTransport(daemonBuild: 9)
        await transport.failUpdatePreparation()
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
        let states = Mutex<[UpdateHandoffState]>([])
        let service = BootoutService()
        await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) {
            try await DaemonUpdateHandoff.run(
                client: client,
                service: service,
                currentBuild: 10,
                grant: Data([1]),
                changed: { value in states.withLock { $0.append(value) } },
            )
        }
        #expect(states.withLock { $0 } == [.finishing])
        #expect(await transport.preparationHadGrant)
        #expect(service.calls.isEmpty)
        #expect(await client.currentConnectionState() == .connected(daemonBuild: 9))
        await client.disconnect()
    }

    @Test
    func `an unregister that never calls back still ends registered once the daemon is gone`() async throws {
        let service = BootoutService(unregister: .hangAfterBootout)
        let states = try await handoff(service, limits: UpdateHandoffLimits(
            unregister: .seconds(60), registration: .seconds(5), statusPoll: .milliseconds(10),
        ))
        #expect(service.calls == ["unregister", "register"])
        #expect(states == [.finishing, .ready])
        service.release()
    }

    @Test
    func `an unregister that never calls back times out and registration goes ahead`() async throws {
        let service = BootoutService(unregister: .hang)
        let states = try await handoff(service, limits: UpdateHandoffLimits(
            unregister: .milliseconds(100), registration: .seconds(5), statusPoll: .milliseconds(10),
        ))
        #expect(service.calls == ["unregister", "register"])
        #expect(states == [.finishing, .ready])
        service.release()
    }

    @Test
    func `a register that always fails is reported after the bounded tries`() async throws {
        let service = BootoutService(register: .fail(.system(code: 22)))
        await #expect(throws: ServiceError.system(code: 22)) {
            _ = try await handoff(service, limits: Self.fast)
        }
        #expect(service.calls == ["unregister", "register", "register", "register"])
    }

    @Test
    func `a first register failure is retried and the hand-off finishes`() async throws {
        let service = BootoutService(register: .failFirst(1, .system(code: 1)))
        let states = try await handoff(service, limits: Self.fast)
        #expect(service.calls == ["unregister", "register", "register"])
        #expect(states == [.finishing, .ready])
    }

    @Test
    func `a host-guard refusal is not retried`() async throws {
        let service = BootoutService(register: .fail(.hostGuard))
        await #expect(throws: ServiceError.hostGuard) {
            _ = try await handoff(service, limits: Self.fast)
        }
        #expect(service.calls == ["unregister", "register"])
    }

    @Test
    func `the ordinary path registers once without waiting`() async throws {
        let service = BootoutService()
        let clock = ContinuousClock()
        let start = clock.now
        let states = try await handoff(service, limits: Self.patient)
        #expect(service.calls == ["unregister", "register"])
        #expect(service.registeredFrom == [.notRegistered])
        #expect(states == [.finishing, .ready])
        #expect(clock.now - start < .seconds(2))
    }

    @Test
    func `a status still registered after unregister delays the first register`() async throws {
        let service = BootoutService(unregister: .returnsBeforeBootout)
        let run = Task { try await handoff(service, limits: Self.patient) }
        while service.calls.isEmpty {
            await Task.yield()
        }
        try await Task.sleep(for: .milliseconds(300))
        #expect(service.calls == ["unregister"])
        service.transition(to: .notRegistered)
        let states = try await run.value
        #expect(service.calls == ["unregister", "register"])
        #expect(service.registeredFrom == [.notRegistered])
        #expect(states == [.finishing, .ready])
    }

    @Test
    func `a bootout that never shows registers after the bound`() async throws {
        let service = BootoutService(unregister: .returnsBeforeBootout)
        let states = try await handoff(service, limits: Self.fast)
        #expect(service.calls == ["unregister", "register"])
        #expect(service.registeredFrom == [.enabled])
        #expect(states == [.finishing, .ready])
    }

    @Test
    func `a final register failure leaves the controller able to register again`() async throws {
        let system = SystemServiceFake(failures: 3)
        let controller = ServiceController(operations: system.operations, isDebugBuild: false)
        await #expect(throws: ServiceError.system(code: 1)) {
            _ = try await handoff(controller, limits: Self.fast)
        }
        #expect(system.registerCalls == 3)
        #expect(controller.lastRegisterFailure == SystemErrorIdentity(domain: "SMAppServiceErrorDomain", code: 1))
        var states = controller.state.makeAsyncIterator()
        #expect(await states.next() == .notRegistered)
        try await controller.register()
        #expect(system.registerCalls == 4)
        #expect(await states.next() == .enabled)
    }

    @Test
    func `a registration that never reaches enabled or approval times out`() async throws {
        let service = BootoutService(register: .stay(.notRegistered))
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: DaemonError.disconnected) {
            _ = try await handoff(service, limits: Self.fast)
        }
        #expect(clock.now - start < .seconds(5))
    }

    @Test
    func `an unregister failure with the daemon still registered never registers`() async throws {
        let service = BootoutService(unregister: .fail(.system(code: 3)))
        await #expect(throws: ServiceError.system(code: 3)) {
            _ = try await handoff(service, limits: Self.fast)
        }
        #expect(service.calls == ["unregister"])
    }

    @Test
    func `an unregister failure after the daemon is gone still registers`() async throws {
        let service = BootoutService(unregister: .failAfterBootout(.system(code: 3)))
        let states = try await handoff(service, limits: Self.fast)
        #expect(service.calls == ["unregister", "register"])
        #expect(states == [.finishing, .ready])
    }

    @Test
    func `approval is awaited past the registration bound`() async throws {
        let service = BootoutService(register: .stay(.requiresApproval))
        let transport = ScriptedStatusTransport(daemonBuild: 9)
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10, minimumDaemonBuild: 1)
        let states = Mutex<[UpdateHandoffState]>([])
        let run = Task {
            try await DaemonUpdateHandoff.run(
                client: client, service: service, currentBuild: 10, grant: Data([1]), limits: Self.fast,
                changed: { value in states.withLock { $0.append(value) } },
            )
        }
        while !states.withLock({ $0.contains(.needsApproval) }) {
            await Task.yield()
        }
        try await Task.sleep(for: .milliseconds(300))
        service.transition(to: .enabled)
        try await run.value
        #expect(states.withLock { $0 } == [.finishing, .needsApproval, .ready])
        await client.disconnect()
    }

    private static let fast = UpdateHandoffLimits(
        unregister: .milliseconds(100), registration: .milliseconds(150), statusPoll: .milliseconds(10),
        bootout: .milliseconds(100), registerAttempts: 3, registerRetryPause: .milliseconds(10),
    )

    /// Bounds far longer than any test waits, so finishing quickly shows that nothing waited for them.
    private static let patient = UpdateHandoffLimits(
        unregister: .seconds(60), registration: .seconds(60), statusPoll: .milliseconds(10),
        bootout: .seconds(60), registerAttempts: 3, registerRetryPause: .seconds(60),
    )

    private func handoff(_ service: any ServiceControlling, limits: UpdateHandoffLimits) async throws -> [UpdateHandoffState] {
        let transport = ScriptedStatusTransport(daemonBuild: 9)
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10, minimumDaemonBuild: 1)
        defer { Task { await client.disconnect() } }
        let states = Mutex<[UpdateHandoffState]>([])
        try await DaemonUpdateHandoff.run(
            client: client, service: service, currentBuild: 10, grant: Data([1]), limits: limits,
            changed: { value in states.withLock { $0.append(value) } },
        )
        #expect(await transport.requests.contains(.prepareForUpdate))
        return states.withLock { $0 }
    }
}

/// Behaves like `ServiceController`: every subscription starts with the current state.
private final class BootoutService: ServiceControlling, ServiceStatusReporting {
    enum Unregister: Sendable {
        case returns, returnsBeforeBootout, hang, hangAfterBootout, fail(ServiceError), failAfterBootout(ServiceError)
    }

    enum Register: Sendable {
        case enables, stay(ServiceState), fail(ServiceError), failFirst(Int, ServiceError)
    }

    private struct Storage {
        var current: ServiceState = .enabled
        var calls: [String] = []
        var registeredFrom: [ServiceState] = []
        var registerFailures = 0
        var observers: [UUID: AsyncStream<ServiceState>.Continuation] = [:]
        var parked: [CheckedContinuation<Void, Never>] = []
    }

    private let unregisterBehaviour: Unregister
    private let registerBehaviour: Register
    private let storage = Mutex(Storage())

    init(unregister: Unregister = .returns, register: Register = .enables) {
        unregisterBehaviour = unregister
        registerBehaviour = register
    }

    var calls: [String] {
        storage.withLock { $0.calls }
    }

    var currentStatus: ServiceState {
        storage.withLock { $0.current }
    }

    var lastRegisterFailure: SystemErrorIdentity? {
        nil
    }

    /// The status each register call saw.
    var registeredFrom: [ServiceState] {
        storage.withLock { $0.registeredFrom }
    }

    var state: AsyncStream<ServiceState> {
        let (stream, continuation) = AsyncStream<ServiceState>.makeStream()
        let id = UUID()
        let current = storage.withLock { storage in
            storage.observers[id] = continuation
            return storage.current
        }
        continuation.onTermination = { [weak self] _ in
            self?.storage.withLock { _ = $0.observers.removeValue(forKey: id) }
        }
        continuation.yield(current)
        return stream
    }

    func unregister() async throws(ServiceError) {
        storage.withLock { $0.calls.append("unregister") }
        switch unregisterBehaviour {
        case .returns:
            transition(to: .notRegistered)
        case .returnsBeforeBootout:
            // unregister returns while launchd still holds the job; the status changes later.
            return
        case .hang:
            await park()
        case .hangAfterBootout:
            // smd boots the daemon out, then skips the unregister callback.
            storage.withLock { $0.current = .notRegistered }
            await park()
        case let .fail(error):
            throw error
        case let .failAfterBootout(error):
            storage.withLock { $0.current = .notRegistered }
            throw error
        }
    }

    func register() async throws(ServiceError) {
        let failures = storage.withLock { storage in
            storage.calls.append("register")
            storage.registeredFrom.append(storage.current)
            return storage.registerFailures
        }
        switch registerBehaviour {
        case .enables: transition(to: .enabled)
        case let .stay(state): transition(to: state)
        case let .fail(error): throw error
        case let .failFirst(count, error) where failures < count:
            storage.withLock { $0.registerFailures += 1 }
            throw error
        case .failFirst: transition(to: .enabled)
        }
    }

    func openApproval() {}

    func transition(to next: ServiceState) {
        let observers = storage.withLock { storage in
            storage.current = next
            return Array(storage.observers.values)
        }
        for observer in observers {
            observer.yield(next)
        }
    }

    /// Resumes any unregister call that is still waiting for its callback.
    func release() {
        let parked = storage.withLock { storage in
            defer { storage.parked = [] }
            return storage.parked
        }
        for continuation in parked {
            continuation.resume()
        }
    }

    private func park() async {
        await withCheckedContinuation { continuation in
            storage.withLock { $0.parked.append(continuation) }
        }
    }
}

/// The system side of a real `ServiceController`: register throws an SMAppService-style NSError a set number of times.
private final class SystemServiceFake: Sendable {
    private struct Storage {
        var status: ServiceState = .enabled
        var registerCalls = 0
    }

    private let failures: Int
    private let storage = Mutex(Storage())

    init(failures: Int) {
        self.failures = failures
    }

    var registerCalls: Int {
        storage.withLock { $0.registerCalls }
    }

    var operations: ServiceController.Operations {
        ServiceController.Operations(
            register: { [self] in
                let call = storage.withLock { storage in
                    storage.registerCalls += 1
                    return storage.registerCalls
                }
                guard call > failures else {
                    throw NSError(domain: "SMAppServiceErrorDomain", code: 1)
                }
                storage.withLock { $0.status = .enabled }
            },
            unregister: { [self] in storage.withLock { $0.status = .notRegistered } },
            status: { [self] in storage.withLock { $0.status } },
            openApproval: {},
            plistExists: { false },
        )
    }
}
