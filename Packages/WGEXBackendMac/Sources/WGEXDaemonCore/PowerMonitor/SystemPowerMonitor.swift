// SPDX-License-Identifier: MIT
import Dispatch
import Foundation
import Synchronization
import WGEXDaemonProtocol
#if os(macOS)
    import IOKit
    import IOKit.pwr_mgt
#endif

private final class PowerSink: Sendable {
    // IOMessage.h expands these through function-like C macros that Swift cannot import.
    private static let willSleep: UInt32 = 0xE000_0280
    private static let hasPoweredOn: UInt32 = 0xE000_0300
    private static let canSleep: UInt32 = 0xE000_0270
    private let sink: AsyncStream<PowerEvent>.Continuation
    fileprivate let connection = Mutex<UInt32>(0)
    fileprivate init(_ sink: AsyncStream<PowerEvent>.Continuation) {
        self.sink = sink
    }

    fileprivate func receive(type: UInt32, argument: UnsafeMutableRawPointer?) {
        #if os(macOS)
            if type == Self.willSleep {
                sink.yield(.sleep)
            }
            if type == Self.hasPoweredOn {
                sink.yield(.wake)
            }
            if type == Self.willSleep || type == Self.canSleep {
                connection.withLock { port in
                    if port != 0 {
                        _ = IOAllowPowerChange(port, Int(bitPattern: argument))
                    }
                }
            }
        #endif
    }
}

/// Observes system sleep and wake notifications.
public actor SystemPowerMonitor: PowerMonitoring {
    #if os(macOS)
        private var notificationPort: IONotificationPortRef?
        private var notifier: io_object_t = 0
        private var connection: io_connect_t = 0
        private var box: PowerSink?
    #endif
    private var sink: AsyncStream<PowerEvent>.Continuation?
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init() {}

    /// Starts observing changes and returns a bounded event stream.
    public func start() throws -> AsyncStream<PowerEvent> {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            guard connection == 0 else { throw DaemonFailure.hostAlreadyStarted }
            let pair = AsyncStream<PowerEvent>.makeStream(bufferingPolicy: .bufferingNewest(16))
            let box = PowerSink(pair.continuation)
            let port = IORegisterForSystemPower(Unmanaged.passUnretained(box).toOpaque(), &notificationPort, { raw, _, type, argument in
                guard let raw else { return }
                Unmanaged<PowerSink>.fromOpaque(raw).takeUnretainedValue().receive(type: type, argument: argument)
            }, &notifier)
            guard port != 0, let notificationPort else { throw DaemonFailure.hostSystem(5) }
            connection = port; box.connection.withLock { $0 = port }; self.box = box; sink = pair.continuation
            IONotificationPortSetDispatchQueue(notificationPort, DispatchQueue(label: "WGEX.power"))
            return pair.stream
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Stops observation and releases owned notification resources.
    public func stop() {
        #if os(macOS)
            if notifier != 0 {
                _ = IODeregisterForSystemPower(&notifier); notifier = 0
            }
            if let notificationPort {
                IONotificationPortSetDispatchQueue(notificationPort, nil); IONotificationPortDestroy(notificationPort)
            }
            notificationPort = nil
            if connection != 0 {
                IOServiceClose(connection); connection = 0
            }
            box = nil
        #endif
        sink?.finish(); sink = nil
    }
}
