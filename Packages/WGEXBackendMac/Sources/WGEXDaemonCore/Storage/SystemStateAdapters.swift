// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol

/// Anti-rollback publication is serialised so competing clients cannot lower the floor.
public final class MinimumBuildFloor: Sendable {
    private let directory: StateDirectory
    private let lock = Mutex<Void>(())
    public init(directory: StateDirectory) {
        self.directory = directory
    }

    public func admit(build: UInt64) throws {
        try lock.withLock { _ in
            let current = try read()
            guard build >= current else { throw DaemonFailure.floorDowngradeDetected }
            if build > current {
                try write(build)
            }
        }
    }

    /// The XPC owner must verify the admin right before calling this method.
    public func allowDowngrade(to build: UInt64) throws {
        try lock.withLock { _ in try write(build) }
    }

    public func read() throws -> UInt64 {
        guard let data = try directory.read("min-build") else { return 0 }
        guard let text = String(data: data, encoding: .utf8), let build = UInt64(text.trimmingCharacters(in: .newlines)) else {
            throw DaemonFailure.stateInvalidDocument
        }
        return build
    }

    private func write(_ build: UInt64) throws {
        try directory.replace("min-build", with: Data("\(build)\n".utf8))
    }
}

/// Explicit startup adapters; constructing these types has no effects.
public enum SystemStateAdapters {
    public static func disableCoreDumps() throws {
        #if WGEX_LAB_BUILD
            guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
        #endif
        var value = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &value) == 0 else { throw DaemonFailure.hostSystem(errno) }
    }

    public static func excludeFromTimeMachine(_ directory: StateDirectory) throws {
        #if WGEX_LAB_BUILD
            guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
        #endif
        var url = directory.root
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }
}
