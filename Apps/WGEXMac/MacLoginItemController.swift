// SPDX-License-Identifier: MIT

#if os(macOS)
    import WGEXDaemonClient

    /// Login-item mutations share the daemon's host guard; fakes never call this adapter.
    public enum MacLoginItemController {
        /// Enables or removes the app login item after checking the host guard.
        public static func setEnabled(_ enabled: Bool) async throws {
            try await ServiceController(operations: .mainAppLoginItem()).setLoginItemEnabled(enabled)
        }
    }
#endif
