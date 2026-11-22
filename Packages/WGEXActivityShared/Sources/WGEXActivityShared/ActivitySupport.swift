// SPDX-License-Identifier: MIT

/// Whether Live Activities are compiled in (iOS only).
public enum ActivitySupport {
    /// True on iOS, where `TunnelActivityAttributes` exists.
    public static var isAvailable: Bool {
        #if canImport(ActivityKit) && os(iOS)
            true
        #else
            false
        #endif
    }
}
