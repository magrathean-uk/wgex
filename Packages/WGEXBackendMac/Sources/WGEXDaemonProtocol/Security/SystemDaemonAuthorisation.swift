// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
#if os(macOS)
    import Foundation
    import Security
    import SystemConfiguration

    /// Security calls of the daemon's recheck; tests model authd instead.
    internal struct DaemonAuthorisationPorts: Sendable {
        internal let importForm: @Sendable (UnsafePointer<AuthorizationExternalForm>, UnsafeMutablePointer<AuthorizationRef?>) -> OSStatus
        internal let copy: @Sendable (AuthorizationRef, UnsafePointer<AuthorizationRights>, AuthorizationFlags) -> OSStatus
        internal let free: @Sendable (AuthorizationRef) -> OSStatus

        internal static var system: Self {
            Self(
                importForm: { AuthorizationCreateFromExternalForm($0, $1) },
                copy: { AuthorizationCopyRights($0, $1, nil, $2, nil) },
                free: { AuthorizationFree($0, []) },
            )
        }
    }

    /// Authorisation database calls of the root daemon's policy; tests model authd instead.
    internal struct AdminRightDatabasePorts: Sendable {
        internal let read: @Sendable (String) -> [String: Any]?
        internal let write: @Sendable (String, [String: Any]) -> Bool
        internal let isRoot: @Sendable () -> Bool

        internal static var system: Self {
            Self(read: { name in
                var value: CFDictionary?
                guard AuthorizationRightGet(name, &value) == errAuthorizationSuccess else { return nil }
                return value as? [String: Any]
            }, write: { name, definition in
                var created: AuthorizationRef?
                guard AuthorizationCreate(nil, nil, [], &created) == errAuthorizationSuccess, let reference = created else {
                    return false
                }
                defer { _ = AuthorizationFree(reference, []) }
                return AuthorizationRightSet(reference, name, definition as CFDictionary, nil, nil, nil) == errAuthorizationSuccess
            }, isRoot: { geteuid() == 0 })
        }
    }

    public extension DaemonAuthorisation {
        /// Resolves current console ownership and verifies an already granted external right.
        /// No authentication UI is requested by the daemon. Tests inject pure closures instead.
        static var system: DaemonAuthorisation {
            makeSystem(policy: .system, ports: .system)
        }

        /// Production composition over injectable Security ports; the console check stays live.
        internal static func makeSystem(policy: AdminRightPolicy, ports: DaemonAuthorisationPorts) -> DaemonAuthorisation {
            DaemonAuthorisation(
                isConsoleUser: { peer in
                    var consoleUID: uid_t = 0
                    guard SCDynamicStoreCopyConsoleUser(nil, &consoleUID, nil) != nil,
                          consoleUID == peer.uid else { return false }
                    var session = SecuritySessionId(peer.auditSessionID)
                    var attributes = SessionAttributeBits()
                    return SessionGetInfo(session, &session, &attributes) == errSessionSuccess
                        && attributes.contains(.sessionHasGraphicAccess)
                },
                hasAdminRight: { bytes, _ in verifyExternalRight(bytes, policy: policy, ports: ports) },
                isAppClient: { peer in isAppProcess(auditToken: peer.auditToken, requirement: appRequirement) },
            )
        }

        /// The app's requirement under the running build's signing policy; the listener already admitted app or CLI.
        internal static var appRequirement: String {
            #if WGEX_LAB_BUILD
                LabPeerRequirements.app(
                    executableURL: Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]), reader: CodeIdentity(),
                )
            #else
                RequirementStrings.current.appRequirement
            #endif
        }

        /// Checks the accepted connection's code, located by its kernel audit token, against the app requirement. The token
        /// carries the process ID version, so a process that reused the peer's PID does not match; there is no PID path.
        /// A missing or malformed token, or any Security failure, means the peer is not the app, so it can never report
        /// Wi-Fi networks (fail closed).
        internal static func isAppProcess(
            auditToken: Data?, requirement: String,
            guest: (CFDictionary) -> SecCode? = systemGuest,
        ) -> Bool {
            guard let auditToken, auditToken.count == MemoryLayout<audit_token_t>.size else { return false }
            var parsed: SecRequirement?
            guard SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess, let parsed else { return false }
            let attributes = [kSecGuestAttributeAudit: auditToken as CFData] as CFDictionary
            guard let code = guest(attributes) else { return false }
            return SecCodeCheckValidity(code, [], parsed) == errSecSuccess
        }

        /// Asks the kernel host for the guest code matching the attributes.
        internal static func systemGuest(_ attributes: CFDictionary) -> SecCode? {
            var code: SecCode?
            guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess else { return nil }
            return code
        }

        /// Non-interactive recheck of the app's held reference: one right, no environment, flags `[]` (never
        /// extendRights, interactionAllowed or preAuthorize) and no output set. authd accepts the app's credential
        /// only while it is younger than the delegate's timeout.
        internal static func verifyExternalRight(_ bytes: Data?, policy: AdminRightPolicy, ports: DaemonAuthorisationPorts) -> Bool {
            policy.validateExternalForm(bytes, byteCount: MemoryLayout<AuthorizationExternalForm>.size) { bytes in
                var form = AuthorizationExternalForm()
                _ = withUnsafeMutableBytes(of: &form) { bytes.copyBytes(to: $0) }
                var imported: AuthorizationRef?
                guard ports.importForm(&form, &imported) == errAuthorizationSuccess, let reference = imported else { return false }
                defer { _ = ports.free(reference) }
                return AuthorisationTable.adminRightName.withCString { name in
                    var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                    return withUnsafeMutablePointer(to: &item) { pointer in
                        var rights = AuthorizationRights(count: 1, items: pointer)
                        return ports.copy(reference, &rights, []) == errAuthorizationSuccess
                    }
                }
            }
        }
    }

    public extension AdminRightPolicy {
        /// The root daemon owns policy creation. Constructing this seam has no effects.
        static var system: AdminRightPolicy {
            makeSystem(ports: .system)
        }

        /// Reads the right and its delegate for every check; only root writes the canonical definition.
        internal static func makeSystem(ports: AdminRightDatabasePorts) -> AdminRightPolicy {
            AdminRightPolicy(read: {
                guard let right = ports.read(AuthorisationTable.adminRightName),
                      let delegate = ports.read(AdminRightDefinition.delegateName),
                      AdminRightDefinition.acceptsDelegate(delegate)
                else { throw DaemonError.notAuthorised(.adminRightRequired) }
                return try AdminRightDefinition(dictionary: right)
            }, write: {
                guard ports.isRoot(), ports.write(AuthorisationTable.adminRightName, AdminRightDefinition.canonicalDictionary) else {
                    throw DaemonError.notAuthorised(.adminRightRequired)
                }
            })
        }
    }
#endif
