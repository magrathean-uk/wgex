// SPDX-License-Identifier: MIT

import Foundation
import os
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
#if os(macOS)
    import ServiceManagement
#endif

/// Registers the privileged daemon (02 §3, ADR-017) and the app's login item.
/// This is the only file that references `SMAppService`.
///
/// Host guard: in Debug builds every system operation is refused with
/// ``ServiceError/hostGuard`` unless `kern.hv_vmm_present == 1`, so a Debug
/// app can never register, unregister or even query either service on a non-VM
/// host. The guard runs before any `SMAppService` call.
public final class ServiceController: ServiceControlling, ServiceStatusReporting {
    /// The system operations behind the guard. Tests inject recording closures;
    /// the system factories contain all ServiceManagement calls.
    public struct Operations: Sendable {
        /// Registers the daemon.
        public var register: @Sendable () throws -> Void
        /// Unregisters the daemon.
        public var unregister: @Sendable () throws -> Void
        /// Current registration state.
        public var status: @Sendable () -> ServiceState
        /// Opens the Login Items approval pane.
        public var openApproval: @Sendable () -> Void

        /// Whether the calling app bundle contains the daemon launchd plist.
        public var plistExists: @Sendable () -> Bool

        /// Creates an operation set.
        public init(
            register: @escaping @Sendable () throws -> Void,
            unregister: @escaping @Sendable () throws -> Void,
            status: @escaping @Sendable () -> ServiceState,
            openApproval: @escaping @Sendable () -> Void,
            plistExists: @escaping @Sendable () -> Bool = { ServiceController.bundledPlistExists() },
        ) {
            self.register = register
            self.unregister = unregister
            self.status = status
            self.openApproval = openApproval
            self.plistExists = plistExists
        }

        /// `SMAppService.daemon(plistName:)`. Never constructed in tests.
        public static func system(plistName: String) -> Operations {
            #if os(macOS)
                Operations(
                    register: { try SMAppService.daemon(plistName: plistName).register() },
                    unregister: { try SMAppService.daemon(plistName: plistName).unregister() },
                    status: { ServiceState(SMAppService.daemon(plistName: plistName).status) },
                    openApproval: { SMAppService.openSystemSettingsLoginItems() },
                    plistExists: { ServiceController.bundledPlistExists(plistName: plistName) },
                )
            #else
                Operations(
                    register: { throw ServiceError.unsupported },
                    unregister: { throw ServiceError.unsupported },
                    status: { .notRegistered },
                    openApproval: {},
                )
            #endif
        }

        /// Registers the main app at login; this bundle has no separate LoginItems helper.
        /// Constructing the closures does not query or mutate ServiceManagement.
        public static func mainAppLoginItem() -> Operations {
            #if os(macOS)
                Operations(
                    register: { try SMAppService.mainApp.register() },
                    unregister: { try SMAppService.mainApp.unregister() },
                    status: { ServiceState(SMAppService.mainApp.status) },
                    openApproval: { SMAppService.openSystemSettingsLoginItems() },
                    plistExists: { false },
                )
            #else
                Operations(
                    register: { throw ServiceError.unsupported },
                    unregister: { throw ServiceError.unsupported },
                    status: { .notRegistered }, openApproval: {}, plistExists: { false },
                )
            #endif
        }
    }

    /// Checks only the calling bundle, without consulting ServiceManagement.
    public static func bundledPlistExists(
        bundleURL: URL = Bundle.main.bundleURL,
        plistName: String = BuildIdentifiers.current.daemonPlistName,
    ) -> Bool {
        FileManager.default.fileExists(atPath: bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons")
            .appendingPathComponent(plistName).path)
    }

    /// True when compiled with `DEBUG`.
    public static var isDebugBuild: Bool {
        #if DEBUG
            true
        #else
            false
        #endif
    }

    private static let logger = Logger(subsystem: BuildIdentifiers.current.logSubsystem, category: "service")

    private let operations: Operations
    private let sysctl: any SysctlReading
    private let isDebugBuild: Bool
    private let continuations = Mutex<[UUID: AsyncStream<ServiceState>.Continuation]>([:])
    private let registerFailure = Mutex<SystemErrorIdentity?>(nil)

    /// Creates a controller. The defaults are the real system; tests pass fakes.
    public init(
        operations: Operations = .system(plistName: BuildIdentifiers.current.daemonPlistName),
        sysctl: any SysctlReading = SystemSysctl(),
        isDebugBuild: Bool = ServiceController.isDebugBuild,
    ) {
        self.operations = operations
        self.sysctl = sysctl
        self.isDebugBuild = isDebugBuild
    }

    /// The guard: Release builds always pass; Debug builds pass only in a VM.
    public static func systemOperationsPermitted(isDebugBuild: Bool, sysctl: any SysctlReading) -> Bool {
        !isDebugBuild || HypervisorPresence.isVirtualMachine(sysctl)
    }

    /// Registration state, starting with the current one; `.notRegistered`
    /// without querying the system while the guard refuses.
    public var state: AsyncStream<ServiceState> {
        let (stream, continuation) = AsyncStream<ServiceState>.makeStream()
        let id = UUID()
        continuations.withLock { $0[id] = continuation }
        continuation.onTermination = { [weak self] _ in
            self?.continuations.withLock { _ = $0.removeValue(forKey: id) }
        }
        continuation.yield(currentState())
        return stream
    }

    /// The current registration state, `.notRegistered` while the guard refuses; publishes nothing.
    public var currentStatus: ServiceState {
        currentState()
    }

    /// Domain and code of the NSError behind the most recent failed system register.
    public var lastRegisterFailure: SystemErrorIdentity? {
        registerFailure.withLock { $0 }
    }

    /// Registers the daemon, or throws ``ServiceError/hostGuard`` without
    /// touching the system when the guard refuses.
    public func register() async throws(ServiceError) {
        try ensurePermitted("register")
        do {
            try operations.register()
        } catch {
            let system = error as NSError
            registerFailure.withLock { $0 = SystemErrorIdentity(domain: system.domain, code: system.code) }
            // SMAppService may throw after recording a daemon that needs approval.
            let state = currentState()
            guard state == .requiresApproval || state == .enabled else {
                Self.logger.error("register failed: domain \(system.domain, privacy: .public) code \(system.code, privacy: .public)")
                // Subscribers see the service as it is, so Settings > Service offers registration again.
                publish(state)
                throw Self.mapped(error)
            }
            registrationSucceeded(state)
            return
        }
        registrationSucceeded(currentState())
    }

    /// Unregisters the daemon, guarded like ``register()``.
    public func unregister() async throws(ServiceError) {
        try ensurePermitted("unregister")
        try perform(operations.unregister)
    }

    /// Uninstall (M05-T10): unregisters only while the service is enabled or awaiting approval, so a retry after a partial
    /// removal, or a login item the user never enabled, is success without a second `SMAppService` call. Never registers.
    /// Guarded like ``register()``: the guard runs before even reading the registration state.
    public func unregisterIfRegistered() async throws(ServiceError) {
        try ensurePermitted("unregisterIfRegistered")
        let state = currentState()
        guard state == .enabled || state == .requiresApproval else { return }
        try perform(operations.unregister)
    }

    /// Publishes a newly observed approval state when the app returns from System Settings.
    public func refresh() {
        publish(currentState())
    }

    /// Changes an app login item using ``Operations/mainAppLoginItem()`` in production.
    /// The host guard runs before even reading its registration state.
    public func setLoginItemEnabled(_ enabled: Bool) async throws(ServiceError) {
        try ensurePermitted("setLoginItemEnabled")
        let state = currentState()
        if enabled {
            if state != .enabled {
                try await register()
            }
        } else if state == .enabled || state == .requiresApproval {
            try await unregister()
        }
    }

    /// Opens the approval pane; a logged no-op while the guard refuses.
    public func openApproval() {
        guard permitted else {
            Self.logger.error("openApproval refused by the host guard (Debug build outside a VM)")
            return
        }
        operations.openApproval()
    }

    private var permitted: Bool {
        Self.systemOperationsPermitted(isDebugBuild: isDebugBuild, sysctl: sysctl)
    }

    private func currentState() -> ServiceState {
        guard permitted else { return .notRegistered }
        let state = operations.status()
        return state == .notFound && operations.plistExists() ? .notRegistered : state
    }

    private func ensurePermitted(_ operation: StaticString) throws(ServiceError) {
        guard permitted else {
            Self.logger.error("\(operation, privacy: .public) refused by the host guard (Debug build outside a VM)")
            throw .hostGuard
        }
    }

    private func perform(_ operation: @Sendable () throws -> Void) throws(ServiceError) {
        do {
            try operation()
        } catch {
            throw Self.mapped(error)
        }
        publish(currentState())
    }

    private static func mapped(_ error: any Error) -> ServiceError {
        (error as? ServiceError) ?? .system(code: (error as NSError).code)
    }

    private func registrationSucceeded(_ state: ServiceState) {
        publish(state)
        if state == .requiresApproval {
            operations.openApproval()
        }
    }

    private func publish(_ state: ServiceState) {
        continuations.withLock { all in
            for continuation in all.values {
                continuation.yield(state)
            }
        }
    }
}

#if os(macOS)
    private extension ServiceState {
        init(_ status: SMAppService.Status) {
            switch status {
            case .enabled: self = .enabled
            case .requiresApproval: self = .requiresApproval
            case .notFound: self = .notFound
            case .notRegistered: self = .notRegistered
            @unknown default: self = .notRegistered
            }
        }
    }
#endif
