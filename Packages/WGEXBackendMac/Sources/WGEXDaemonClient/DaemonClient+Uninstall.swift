// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

public extension DaemonClient {
    /// Runs the daemon's uninstall (M05-T07) with the admin right's external form (`SystemSecureInstallAuthorisation.grant()`,
    /// held until this returns). Returns when every step is done; a failed step throws `DaemonError.uninstallFailed(step:)`
    /// and calling again resumes there. The caller unregisters the daemon and login item afterwards (DEC-037).
    func uninstall(purgeState: Bool, authorization: Data?) async throws {
        guard case .ok = try await request(.uninstall(purgeState: purgeState), authorization: authorization) else {
            throw DaemonError.malformedMessage
        }
    }
}
