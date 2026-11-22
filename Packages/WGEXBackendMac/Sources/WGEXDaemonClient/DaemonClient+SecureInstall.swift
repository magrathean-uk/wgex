// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

public extension DaemonClient {
    func secureInstallStatus() async throws -> SecureInstallReport {
        guard case let .secureInstall(report) = try await request(.secureInstallStatus) else { throw DaemonError.malformedMessage }
        if report.state == .verified {
            secureInstallVerified()
        }
        return report
    }

    /// The external form is carried by the existing envelope, never by a secrets argument.
    func performSecureInstall(authorization: Data? = nil) async throws -> SecureInstallReport {
        guard case let .secureInstall(report) = try await request(.performSecureInstall, authorization: authorization) else {
            throw DaemonError.malformedMessage
        }
        return await (try? secureInstallStatus()) ?? report
    }
}
