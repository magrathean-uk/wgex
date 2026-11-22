// SPDX-License-Identifier: MIT
import Foundation
import SystemConfiguration
import WGEXDaemonProtocol

/// Observes the active console user without changing login state.
public actor SystemLoginSessionMonitor: LoginSessionMonitoring {
    private let notifications = SystemConfigurationNotifications()
    private var task: Task<Void, Never>?
    private var sink: AsyncStream<UInt32?>.Continuation?
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init() {}
    deinit { task?.cancel() }
    /// Starts observing changes and returns a bounded event stream.
    public func start() async throws -> AsyncStream<UInt32?> {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            guard task == nil else { throw DaemonFailure.hostAlreadyStarted }
            let changes = try await notifications.start(consoleOnly: true)
            let pair = AsyncStream<UInt32?>.makeStream(bufferingPolicy: .bufferingNewest(16))
            sink = pair.continuation
            task = Task {
                for await _ in changes {
                    var uid: uid_t = 0, gid: gid_t = 0
                    let user = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String?
                    pair.continuation.yield(user == nil || user == "loginwindow" || uid == 0 ? nil : uid)
                }
            }
            return pair.stream
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Stops observation and releases owned notification resources.
    public func stop() async {
        task?.cancel(); task = nil; await notifications.stop(); sink?.finish(); sink = nil
    }
}
