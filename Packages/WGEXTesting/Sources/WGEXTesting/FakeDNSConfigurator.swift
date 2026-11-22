// SPDX-License-Identifier: MIT

import Synchronization
import WGEXCore

/// ``DNSConfigurating`` stand-in; fault points `apply` and `remove`.
public final class FakeDNSConfigurator: DNSConfigurating {
    /// Faults consumed by the operations.
    public let faults: FaultInjector
    private let published = Mutex<(generation: Generation, configuration: DNSConfiguration)?>(nil)

    /// Creates a configurator with nothing published.
    public init(faults: FaultInjector = FaultInjector()) {
        self.faults = faults
    }

    /// Generation that published the current configuration.
    public var publishingGeneration: Generation? {
        published.withLock { $0?.generation }
    }

    /// Publishes the configuration.
    public func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonPortError) {
        if let error = faults.fault(at: "apply", as: DaemonPortError.self) {
            throw error
        }
        published.withLock { $0 = (generation, configuration) }
    }

    /// Withdraws the configuration when `generation` published it.
    public func remove(generation: Generation) async throws(DaemonPortError) {
        if let error = faults.fault(at: "remove", as: DaemonPortError.self) {
            throw error
        }
        try published.withLock { (current: inout (generation: Generation, configuration: DNSConfiguration)?) throws(DaemonPortError) in
            guard current?.generation == generation else { throw .notOwned }
            current = nil
        }
    }

    /// The published configuration.
    public func current() async -> DNSConfiguration? {
        published.withLock { $0?.configuration }
    }
}
