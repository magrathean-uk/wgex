// SPDX-License-Identifier: MIT

import WGEXCore

/// Parameters of one engine instance (`wgex_create_params`, 02 §6.2) minus
/// the callbacks, which the engine actor owns.
public struct EngineConfiguration: Sendable, Hashable {
    /// How the engine obtains its tun device.
    public enum Tun: Sendable, Hashable {
        /// Kind 0: utun descriptor from Network Extension (MTU managed by NE).
        case networkExtension(descriptor: Int32)
        /// Kind 1: packet socketpair end, one IP packet per datagram (tests).
        case packetDescriptor(descriptor: Int32, mtu: Int32)
        /// Kind 2: create a utun (root, Mac daemon).
        case createUTun(mtu: Int32)
    }

    /// Process-wide memory settings (`wgex_process_params`).
    public struct ProcessLimits: Sendable, Hashable {
        /// Constrained profile for extensions (02 §6.3).
        public static let constrained = ProcessLimits(memoryLimitBytes: 24 << 20, gcPercent: 50, queueProfile: 1)

        /// Go memory limit in bytes.
        public var memoryLimitBytes: Int64
        /// Go GC percentage.
        public var gcPercent: Int32
        /// Queue profile (ignored on macOS).
        public var queueProfile: Int32

        /// Creates limits.
        public init(memoryLimitBytes: Int64, gcPercent: Int32, queueProfile: Int32) {
            self.memoryLimitBytes = memoryLimitBytes
            self.gcPercent = gcPercent
            self.queueProfile = queueProfile
        }
    }

    /// Minimum engine log level; debug work is disabled unless explicitly requested.
    public enum LogLevel: Int32, Sendable, Hashable {
        /// Info and errors (default).
        case info = 0
        /// Debug, info and errors.
        case debug = 1
        /// Errors only.
        case error = 2
        /// Disable all engine log work.
        case off = 3
    }

    /// Logging threshold, applied before formatting or redaction.
    public var logLevel: LogLevel

    /// Tun source.
    public var tun: Tun
    /// Underlay interface index for IPv4 sockets; nil leaves them unbound.
    public var bindInterfaceIndexV4: UInt32?
    /// Underlay interface index for IPv6 sockets; nil leaves them unbound.
    public var bindInterfaceIndexV6: UInt32?
    /// Inner transport.
    public var transport: TransportSpec
    /// Apply the mobile roaming quirk after each configuration (iOS, tvOS).
    public var mobileQuirks: Bool
    /// Process-wide limits applied by the first engine in the process.
    public var processLimits: ProcessLimits?

    /// Creates a configuration.
    public init(
        tun: Tun,
        bindInterfaceIndexV4: UInt32? = nil,
        bindInterfaceIndexV6: UInt32? = nil,
        transport: TransportSpec = .udp,
        mobileQuirks: Bool = false,
        processLimits: ProcessLimits? = nil,
        logLevel: LogLevel = .info,
    ) {
        self.logLevel = logLevel
        self.tun = tun
        self.bindInterfaceIndexV4 = bindInterfaceIndexV4
        self.bindInterfaceIndexV6 = bindInterfaceIndexV6
        self.transport = transport
        self.mobileQuirks = mobileQuirks
        self.processLimits = processLimits
    }
}
