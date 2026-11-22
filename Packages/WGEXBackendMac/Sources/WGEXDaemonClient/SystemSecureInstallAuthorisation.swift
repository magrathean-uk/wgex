// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
#if os(macOS)
    import Security
#endif

/// An admin right the app obtained, carried to the daemon as an external form. The grant must
/// outlive the daemon's verification: freeing the underlying AuthorizationRef invalidates the
/// external form, so the composition holds the grant until the privileged request has replied.
public protocol SecureInstallGrant: Sendable {
    var externalForm: Data { get }
}

/// Tests pass raw bytes; no Security call is involved.
extension Data: SecureInstallGrant {
    public var externalForm: Data {
        self
    }
}

/// Explicit app-only authentication port. Tests inject a closure instead of invoking Security UI.
public enum SystemSecureInstallAuthorisation {
    #if os(macOS)
        /// Owns the AuthorizationRef for as long as the daemon may still verify its external form.
        public final class Grant: SecureInstallGrant, @unchecked Sendable {
            public let externalForm: Data
            private let reference: AuthorizationRef

            fileprivate init(reference: AuthorizationRef, externalForm: Data) {
                self.reference = reference; self.externalForm = externalForm
            }

            deinit { _ = AuthorizationFree(reference, []) }
        }
    #endif

    /// Converts the Security result without losing an explicit dismissal of the admin prompt.
    public static func checkGrantResult(_ status: Int32) throws {
        #if os(macOS)
            if status == errAuthorizationCanceled {
                throw TunnelError.cancelled
            }
            guard status == errAuthorizationSuccess else { throw DaemonError.notAuthorised(.adminRightRequired) }
        #else
            throw ServiceError.unsupported
        #endif
    }

    /// Runs the blocking Security interaction on the concurrent executor, never the UI actor.
    @concurrent
    public static func grant() async throws -> any SecureInstallGrant {
        #if os(macOS) && (WGEX_LAB_BUILD || !DEBUG)
            #if WGEX_LAB_BUILD
                // Client-side early refusal; the daemon independently enforces the full LabGuard.
                guard HypervisorPresence.isVirtualMachine(SystemSysctl()) else { throw ServiceError.hostGuard }
            #endif
            var created: AuthorizationRef?
            guard AuthorizationCreate(nil, nil, [], &created) == errAuthorizationSuccess, let reference = created else {
                throw DaemonError.notAuthorised(.adminRightRequired)
            }
            // Freed by the grant's deinit once the daemon has replied, never here (lab run, 26 Oct 2026:
            // an eagerly freed reference left the daemon with an unusable external form).
            do {
                return try Grant(reference: reference, externalForm: AuthorisationTable.adminRightName.withCString { name in
                    // Only the root daemon creates the right; the app refuses an unsafe database rule too.
                    guard AdminRightPolicy.system.isValid() else { throw DaemonError.notAuthorised(.adminRightRequired) }
                    var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                    return try withUnsafeMutablePointer(to: &item) { pointer in
                        var rights = AuthorizationRights(count: 1, items: pointer)
                        // No preAuthorize: that flag returns success without obtaining the credential,
                        // so the external form would carry nothing for the daemon to verify (lab run, 26 Oct 2026).
                        try checkGrantResult(AuthorizationCopyRights(reference, &rights, nil, [.interactionAllowed, .extendRights], nil))
                        var form = AuthorizationExternalForm()
                        guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else {
                            throw DaemonError.notAuthorised(.adminRightRequired)
                        }
                        return withUnsafeBytes(of: &form) { Data($0) }
                    }
                })
            } catch {
                _ = AuthorizationFree(reference, [])
                throw error
            }
        #else
            throw ServiceError.hostGuard
        #endif
    }
}
