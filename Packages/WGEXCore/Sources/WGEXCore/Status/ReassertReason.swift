// SPDX-License-Identifier: MIT

/// Why an active tunnel is re-establishing (02 §4.1).
public enum ReassertReason: String, Codable, Sendable, Hashable, CaseIterable {
    /// The underlying network path changed.
    case pathChanged
    /// The device woke from sleep.
    case wake
    /// The transport was switched.
    case transportSwitch
    /// The next endpoint candidate is being tried.
    case endpointRotation
}
