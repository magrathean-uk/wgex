// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    /// Lab-only hooks read from the lab marker file as JSON (ADR-017). Unknown
    /// keys are ignored; an empty marker means no hooks.
    public struct LabHooks: Codable, Sendable, Hashable {
        /// Crash-matrix point at which the daemon aborts (P4 crash matrix).
        public var crashAt: String?
        /// Allow the development bundle path for daemon tests.
        public var allowDevPath: Bool?

        /// Creates a hook set.
        public init(crashAt: String? = nil, allowDevPath: Bool? = nil) {
            self.crashAt = crashAt
            self.allowDevPath = allowDevPath
        }
    }

#endif
