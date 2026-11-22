// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXDaemonProtocol

/// A profile whose on-demand claim ended and whose release the controller still owes (ADR-030 sections 6 and 7).
/// `stopsIntent`: the release stops the profile's intent, whatever started it (a disarm, an arm of another profile);
/// otherwise it only drops the armed secret retention (an install that cleared the policy, a manual connect of another
/// profile, a removal), and only if no other retention reason holds by then. Every newer claim on the profile discharges
/// the owed stop in a durable write before it reserves (a manual start or a boot reservation keeps the retention-only
/// release; arming drops it), so a release never stops a claim made after it.
public struct OnDemandRelease: Codable, Sendable, Hashable {
    public let profileID: UUID
    public let stopsIntent: Bool
    public init(profileID: UUID, stopsIntent: Bool) {
        self.profileID = profileID; self.stopsIntent = stopsIntent
    }
}

/// The whole durable on-demand state in one record, replaced atomically (temporary file, rename, fsync): the armed profile
/// and the releases still owed. One write moves the selection and records what it released, so no crash can leave a
/// switch half done; a profile is armed only while this record names it and its registration still compiles a macOS rule.
public struct OnDemandRecord: Codable, Sendable, Equatable {
    public var armed: UUID?
    public var releases: [OnDemandRelease]

    public init(armed: UUID? = nil, releases: [OnDemandRelease] = []) {
        self.armed = armed; self.releases = releases
    }

    /// Records that `id`'s on-demand claim ended; an owed stop is never weakened by a later retention-only release.
    internal mutating func release(_ id: UUID, stopsIntent: Bool) {
        let owed = releases.first { $0.profileID == id }?.stopsIntent ?? false
        releases.removeAll { $0.profileID == id }
        releases.append(OnDemandRelease(profileID: id, stopsIntent: stopsIntent || owed))
    }

    /// Arming `id` supersedes whatever release it was owed.
    internal mutating func claim(_ id: UUID) {
        releases.removeAll { $0.profileID == id }
    }

    /// A newer intent claim on `id` discharges the stop it was owed; dropping the retention still re-checks at completion.
    internal mutating func dischargeStop(_ id: UUID) {
        releases = releases.map { $0.profileID == id ? OnDemandRelease(profileID: id, stopsIntent: false) : $0 }
    }
}

/// The armed registration as committed, with the registry's commit version. Versions grow with every committed mutation
/// within one daemon process, so a cache applies only selections at least as new as the one it holds.
public struct ArmedSelection: Sendable, Equatable {
    public let record: RegisteredProfile?
    public let version: UInt64
}

/// A committed arm: the new selection and every release the record still owes after it (the profile it took the selection
/// from, and any release an earlier command left), which the controller completes in the same control admission.
public struct ArmCommit: Sendable, Equatable {
    public let selection: ArmedSelection
    public let releases: [OnDemandRelease]
}

/// Nondurable repositories keep no on-demand record; the registry holds it in memory for its lifetime.
public extension ProfileRepository {
    func loadOnDemandRecord() throws -> OnDemandRecord? {
        nil
    }

    func saveOnDemandRecord(_: OnDemandRecord) throws {}
}
