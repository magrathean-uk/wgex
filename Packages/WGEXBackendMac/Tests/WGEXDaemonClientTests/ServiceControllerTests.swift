// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

/// None of these tests uses `ServiceController.Operations.system`: every
/// operation is a recording closure, so no test can reach `SMAppService`.
private struct ServiceControllerTests {
    private struct FixedSysctl: SysctlReading {
        let value: Int64?
        func integer(named _: String) -> Int64? {
            value
        }
    }

    private final class Recorder: Sendable {
        let calls = Mutex<[String]>([])
        let state: ServiceState

        init(state: ServiceState = .requiresApproval) {
            self.state = state
        }

        var operations: ServiceController.Operations {
            ServiceController.Operations(
                register: { self.calls.withLock { $0.append("register") } },
                unregister: { self.calls.withLock { $0.append("unregister") } },
                status: {
                    self.calls.withLock { $0.append("status") }
                    return self.state
                },
                openApproval: { self.calls.withLock { $0.append("openApproval") } },
            )
        }
    }

    private static var hostIsVirtualMachine: Bool {
        HypervisorPresence.isVirtualMachine(SystemSysctl())
    }

    @Test(.enabled(if: !hostIsVirtualMachine, "proves the guard on a physical host"))
    func `register is never reached on this host`() async {
        let recorder = Recorder()
        let controller = ServiceController(operations: recorder.operations, isDebugBuild: true)
        await #expect(throws: ServiceError.hostGuard) { try await controller.register() }
        await #expect(throws: ServiceError.hostGuard) { try await controller.unregister() }
        await #expect(throws: ServiceError.hostGuard) { try await controller.setLoginItemEnabled(true) }
        await #expect(throws: ServiceError.hostGuard) { try await controller.setLoginItemEnabled(false) }
        controller.openApproval()
        var states = controller.state.makeAsyncIterator()
        #expect(await states.next() == .notRegistered)
        #expect(recorder.calls.withLock { $0 }.isEmpty)
    }

    @Test(arguments: [Int64?.none, 0, 2])
    func `debug builds refuse outside a VM`(value: Int64?) async {
        let recorder = Recorder()
        let controller = ServiceController(operations: recorder.operations, sysctl: FixedSysctl(value: value), isDebugBuild: true)
        await #expect(throws: ServiceError.hostGuard) { try await controller.register() }
        #expect(recorder.calls.withLock { $0 }.isEmpty)
    }

    @Test
    func `debug builds proceed inside a VM`() async throws {
        let recorder = Recorder()
        let controller = ServiceController(operations: recorder.operations, sysctl: FixedSysctl(value: 1), isDebugBuild: true)
        try await controller.register()
        #expect(recorder.calls.withLock { $0 }.first == "register")
    }

    @Test
    func `release builds are not guarded`() async throws {
        let recorder = Recorder()
        let controller = ServiceController(operations: recorder.operations, sysctl: FixedSysctl(value: 0), isDebugBuild: false)
        try await controller.register()
        #expect(recorder.calls.withLock { $0 }.contains("register"))
    }

    @Test(arguments: [Int64?.none, 0, 2], [false, true])
    func `login item refuses before status or mutation outside a debug VM`(value: Int64?, enabled: Bool) async {
        let recorder = Recorder()
        let controller = ServiceController(operations: recorder.operations, sysctl: FixedSysctl(value: value), isDebugBuild: true)
        await #expect(throws: ServiceError.hostGuard) { try await controller.setLoginItemEnabled(enabled) }
        #expect(recorder.calls.withLock { $0 }.isEmpty)
    }

    @Test(arguments: [ServiceState.enabled, .requiresApproval, .notRegistered, .notFound], [false, true])
    func `login item enables idempotently in a debug VM or release build`(state: ServiceState, debug: Bool) async throws {
        let recorder = Recorder(state: state)
        let controller = ServiceController(
            operations: recorder.operations, sysctl: FixedSysctl(value: debug ? 1 : 0), isDebugBuild: debug,
        )
        try await controller.setLoginItemEnabled(true)
        let expected = state == .enabled ? ["status"] : ["status", "register", "status"]
            + (state == .requiresApproval ? ["openApproval"] : [])
        #expect(recorder.calls.withLock { $0 } == expected)
    }

    @Test(arguments: [ServiceState.enabled, .requiresApproval, .notRegistered, .notFound], [false, true])
    func `login item removes only registered or pending entries`(state: ServiceState, debug: Bool) async throws {
        let recorder = Recorder(state: state)
        let controller = ServiceController(
            operations: recorder.operations, sysctl: FixedSysctl(value: debug ? 1 : 0), isDebugBuild: debug,
        )
        try await controller.setLoginItemEnabled(false)
        let expected = state == .enabled || state == .requiresApproval ? ["status", "unregister", "status"] : ["status"]
        #expect(recorder.calls.withLock { $0 } == expected)
    }

    @Test(arguments: [false, true])
    func `login item mutation failures retain the mapped error`(enabled: Bool) async {
        let operations = ServiceController.Operations(
            register: { throw NSError(domain: "fixture", code: 42) },
            unregister: { throw NSError(domain: "fixture", code: 42) },
            status: { enabled ? .notRegistered : .enabled }, openApproval: {}, plistExists: { false },
        )
        let controller = ServiceController(operations: operations, isDebugBuild: false)
        await #expect(throws: ServiceError.system(code: 42)) { try await controller.setLoginItemEnabled(enabled) }
    }

    @Test
    func `build flag matches the configuration`() {
        #if DEBUG
            #expect(ServiceController.isDebugBuild)
        #else
            #expect(!ServiceController.isDebugBuild)
        #endif
    }

    @Test(arguments: [false, true])
    func `notFound means unregistered only when the bundled plist exists`(_ exists: Bool) async {
        let operations = ServiceController.Operations(
            register: {}, unregister: {}, status: { .notFound }, openApproval: {}, plistExists: { exists },
        )
        let controller = ServiceController(operations: operations, isDebugBuild: false)
        var states = controller.state.makeAsyncIterator()
        #expect(await states.next() == (exists ? .notRegistered : .notFound))
    }

    @Test(arguments: [ServiceState.requiresApproval, .enabled])
    func `register throw with recorded success publishes state and opens approval when needed`(_ result: ServiceState) async throws {
        let calls = Mutex<[String]>([])
        let state = Mutex<ServiceState>(.notRegistered)
        let operations = ServiceController.Operations(
            register: {
                calls.withLock { $0.append("register") }
                state.withLock { $0 = result }
                throw NSError(domain: "fixture", code: 42)
            },
            unregister: {},
            status: { calls.withLock { $0.append("status") }; return state.withLock { $0 } },
            openApproval: { calls.withLock { $0.append("approval") } },
            plistExists: { true },
        )
        let controller = ServiceController(operations: operations, isDebugBuild: false)
        var states = controller.state.makeAsyncIterator()
        #expect(await states.next() == .notRegistered)
        try await controller.register()
        #expect(await states.next() == result)
        #expect(calls.withLock { $0 } == ["status", "register", "status"] + (result == .requiresApproval ? ["approval"] : []))
    }

    @Test(arguments: [ServiceState.notRegistered, .notFound])
    func `failed registration keeps the original mapped error`(_ result: ServiceState) async {
        let calls = Mutex<[String]>([])
        let operations = ServiceController.Operations(
            register: { calls.withLock { $0.append("register") }; throw NSError(domain: "fixture", code: 42) },
            unregister: {},
            status: { calls.withLock { $0.append("status") }; return result },
            openApproval: { calls.withLock { $0.append("approval") } },
            plistExists: { false },
        )
        let controller = ServiceController(operations: operations, isDebugBuild: false)
        await #expect(throws: ServiceError.system(code: 42)) { try await controller.register() }
        #expect(calls.withLock { $0 } == ["register", "status"])
    }

    @Test
    func `failed registration preserves an existing service error`() async {
        let operations = ServiceController.Operations(
            register: { throw ServiceError.unsupported }, unregister: {}, status: { .notRegistered }, openApproval: {},
            plistExists: { true },
        )
        let controller = ServiceController(operations: operations, isDebugBuild: false)
        await #expect(throws: ServiceError.unsupported) { try await controller.register() }
    }
}
