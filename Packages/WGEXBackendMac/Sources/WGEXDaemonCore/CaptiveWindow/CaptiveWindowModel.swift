// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

public enum CaptiveWindowModel {
    public static func open(seconds: Int, maximum: Int, continuous: Duration, wall: Date) throws -> CaptiveWindowRecord {
        guard (1 ... max(1, maximum)).contains(seconds) else { throw DaemonFailure.captiveInvalidDuration }
        return CaptiveWindowRecord(
            expiresAtWall: wall.addingTimeInterval(TimeInterval(seconds)),
            expiresAtContinuousSeconds: continuous.components.seconds + Int64(seconds),
            expiresAtContinuousAttoseconds: continuous.components.attoseconds,
        )
    }

    public static func extend(
        _ record: CaptiveWindowRecord, seconds: Int, maximum: Int, continuous: Duration, wall: Date,
    ) throws -> CaptiveWindowRecord {
        guard !record.extended else { throw DaemonFailure.captiveAlreadyExtended }
        guard !isExpired(record, continuous: continuous) else { throw DaemonFailure.captiveExpired }
        let next = try open(seconds: seconds, maximum: maximum, continuous: continuous, wall: wall)
        let deadline = max(record.continuousDeadline, next.continuousDeadline)
        return CaptiveWindowRecord(
            expiresAtWall: max(record.expiresAtWall, next.expiresAtWall),
            expiresAtContinuousSeconds: deadline.components.seconds,
            expiresAtContinuousAttoseconds: deadline.components.attoseconds, extended: true,
        )
    }

    /// Continuous time is authoritative during this process. A new process never trusts this deadline.
    public static func isExpired(_ record: CaptiveWindowRecord, continuous: Duration, sameProcess: Bool = true) -> Bool {
        !sameProcess || continuous >= record.continuousDeadline
    }
}
