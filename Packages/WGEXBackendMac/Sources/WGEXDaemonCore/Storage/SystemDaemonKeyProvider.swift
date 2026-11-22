// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import LocalAuthentication
    import os
    import Security
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore

    /// System-keychain storage restricted to the installed daemon's designated code requirement.
    /// Security's trusted-application object captures that requirement; ad hoc signing captures the cdhash.
    public struct SystemDaemonKeyProvider: DaemonKeyProvisioning, DaemonKeyRemoving {
        private struct RemovalOperations: Sendable {
            let guardDaemon: @Sendable () throws -> Void
            let exists: @Sendable () throws -> Bool
            let delete: @Sendable () throws -> Void
        }

        private let removalOperations: RemovalOperations?

        /// Constructing the provider neither reads nor writes a keychain.
        public init() {
            removalOperations = nil
        }

        /// Replaces platform operations so tests exercise removal without touching the host keychain.
        package init(
            guardDaemon: @escaping @Sendable () throws -> Void,
            exists: @escaping @Sendable () throws -> Bool,
            delete: @escaping @Sendable () throws -> Void,
        ) {
            removalOperations = RemovalOperations(guardDaemon: guardDaemon, exists: exists, delete: delete)
        }

        /// Isolates the legacy System-keychain API behind the non-deprecated provider protocol.
        @available(macOS, deprecated: 26.0, message: "System wrapping keys require the legacy keychain ACL API")
        public func wrappingKey() throws -> SecretBytes {
            try Self.guardDaemon()
            return try WrappingKeyReadPolicy(
                read: { try Self.read() },
                legacyAccess: { try Self.hasLegacyACL(Self.keychain()) },
                warnLegacy: { Logger(subsystem: BuildIdentifiers.daemonService, category: "wrapping-key").warning("legacyACL") },
            ).wrappingKey()
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func read() throws -> SecretBytes {
            let keychain = try Self.keychain()
            var query = Self.query(keychain)
            query[kSecReturnData] = true
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            try Self.check(status)
            guard let result, CFGetTypeID(result) == CFDataGetTypeID() else { throw SecretStoreError.unavailable }
            let data = unsafeDowncast(result, to: CFData.self)
            let length = CFDataGetLength(data)
            let pointer = CFDataGetBytePtr(data)
            defer {
                if let pointer {
                    _ = memset_s(UnsafeMutableRawPointer(mutating: pointer), length, 0, length)
                }
            }
            guard length == 32 else { throw SecretStoreError.unavailable }
            return try SecretBytes(copying: UnsafeRawBufferPointer(start: pointer, count: length))
        }

        /// Called only after secure bundle repair; never replaces an existing key.
        @available(macOS, deprecated: 26.0, message: "System wrapping keys require the legacy keychain ACL API")
        public func provision() throws {
            try Self.guardDaemon()
            try WrappingKeyProvisioner(read: { try Self.read() }, create: { try Self.add($0) }, generate: {
                var bytes = try SecretBytes(zeroedCount: 32)
                try bytes.withUnsafeMutableBytes { raw in
                    guard let base = raw.baseAddress, SecRandomCopyBytes(kSecRandomDefault, raw.count, base) == errSecSuccess else {
                        throw SecretStoreError.unavailable
                    }
                }
                return bytes
            }, repairAccess: { try Self.repairAccess() }, legacyAccess: { try Self.hasLegacyACL(Self.keychain()) }, hasEncryptedState: {
                let directory = try StateDirectory(root: URL(fileURLWithPath: "/Library/Application Support/WGEX"), ownerUID: 0)
                let secrets = try directory.directory("secrets")
                let bundles = try secrets.directory("bundles")
                return try secrets.filenames().contains { $0.hasSuffix(".blob") }
                    || bundles.filenames().contains { $0.hasSuffix(".blob") }
            }).provision()
        }

        /// Uninstall (M05-T07): deletes the System-keychain wrapping key; a key that is already gone is success.
        @available(macOS, deprecated: 26.0, message: "System wrapping keys require the legacy keychain ACL API")
        public func removeWrappingKey() throws {
            let operations: RemovalOperations
            if let removalOperations {
                operations = removalOperations
            } else {
                try Self.guardHost()
                guard geteuid() == 0 else { throw SecretStoreError.unavailable }
                operations = RemovalOperations(
                    guardDaemon: { try Self.guardDaemon() },
                    exists: { try Self.wrappingKeyExists() },
                    delete: { try Self.deleteWrappingKey() },
                )
            }
            guard try operations.exists() else { return }
            try operations.guardDaemon()
            try operations.delete()
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func wrappingKeyExists() throws -> Bool {
            var query = try Self.query(Self.keychain())
            query[kSecReturnAttributes] = true
            let status = SecItemCopyMatching(query as CFDictionary, nil)
            guard status != errSecItemNotFound else { return false }
            try Self.check(status)
            return true
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func deleteWrappingKey() throws {
            var query = try Self.query(Self.keychain())
            query.removeValue(forKey: kSecMatchLimit)
            let status = SecItemDelete(query as CFDictionary)
            guard status != errSecItemNotFound else { return }
            try Self.check(status)
        }

        private static func guardDaemon() throws {
            try guardHost()
            guard geteuid() == 0, Bundle.main.executableURL?.path == "/Applications/WGEX.app/Contents/MacOS/WGEXDaemon" else {
                throw SecretStoreError.unavailable
            }
        }

        private static func guardHost() throws {
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #elseif DEBUG
                guard !HostGuard.refuseOwnerMac() else { throw SecretStoreError.unavailable }
            #endif
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func keychain() throws -> SecKeychain {
            try check(SecKeychainSetUserInteractionAllowed(false))
            var keychain: SecKeychain?
            try check(SecKeychainOpen("/Library/Keychains/System.keychain", &keychain))
            guard let keychain else { throw SecretStoreError.unavailable }
            return keychain
        }

        private static func query(_ keychain: SecKeychain) -> [CFString: Any] {
            let context = LAContext(); context.interactionNotAllowed = true
            return [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: BuildIdentifiers.daemonService,
                kSecAttrAccount: "wrapping-key-v1",
                kSecMatchSearchList: [keychain],
                kSecMatchLimit: kSecMatchLimitOne,
                kSecUseAuthenticationContext: context,
            ]
        }

        private static func check(_ status: OSStatus) throws {
            switch status {
            case errSecSuccess: return
            case errSecItemNotFound: throw SecretStoreError.notFound
            case errSecDuplicateItem: throw SecretStoreError.duplicate
            case errSecInteractionNotAllowed, errSecNotAvailable: throw SecretStoreError.locked
            default: throw SecretStoreError.unavailable
            }
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func trustedDaemon() throws -> SecTrustedApplication {
            guard let url = Bundle.main.executableURL else { throw SecretStoreError.unavailable }
            var code: SecStaticCode?
            var designated: SecRequirement?
            try check(SecStaticCodeCreateWithPath(url as CFURL, [], &code))
            guard let code else { throw SecretStoreError.unavailable }
            try check(SecCodeCopyDesignatedRequirement(code, [], &designated))
            guard let designated else { throw SecretStoreError.unavailable }
            try check(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), designated))
            #if WGEX_LAB_BUILD
                var text: CFString?
                try check(SecRequirementCopyString(designated, [], &text))
                guard let text, (text as String).contains("cdhash") else { throw SecretStoreError.unavailable }
            #endif
            var trusted: SecTrustedApplication?
            try check(SecTrustedApplicationCreateFromPath(url.path, &trusted))
            guard let trusted else { throw SecretStoreError.unavailable }
            return trusted
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func add(_ key: borrowing SecretBytes) throws {
            let keychain = try keychain()
            var access: SecAccess?
            try check(SecAccessCreate("WGEX daemon wrapping key" as CFString, [trustedDaemon()] as CFArray, &access))
            guard let access else { throw SecretStoreError.unavailable }
            try key.withUnsafeBytes { raw in
                guard let data = CFDataCreateWithBytesNoCopy(
                    kCFAllocatorDefault,
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    raw.count,
                    kCFAllocatorNull,
                ) else {
                    throw SecretStoreError.unavailable
                }
                var attributes: [CFString: Any] = [
                    kSecClass: kSecClassGenericPassword, kSecAttrService: BuildIdentifiers.daemonService,
                    kSecAttrAccount: "wrapping-key-v1", kSecUseKeychain: keychain, kSecAttrAccess: access,
                    kSecValueData: data,
                ]
                let context = LAContext(); context.interactionNotAllowed = true
                attributes[kSecUseAuthenticationContext] = context
                try check(SecItemAdd(attributes as CFDictionary, nil))
            }
        }

        /// Changes only the existing item's ACL, including after an ad hoc Lab cdhash changes.
        /// The caller is the owner-authorised secure-install path; key bytes are never updated.
        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func repairAccess() throws {
            let keychain = try keychain()
            // The provisioner reaches this only after an unreadable key or an observed legacy ACL.
            let item = try existingItem(keychain)
            var access: SecAccess?
            try check(SecAccessCreate("WGEX daemon wrapping key" as CFString, [trustedDaemon()] as CFArray, &access))
            guard let access else { throw SecretStoreError.unavailable }
            try check(SecKeychainItemSetAccess(item, access))
        }

        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func existingItem(_ keychain: SecKeychain) throws -> SecKeychainItem {
            var query = query(keychain); query[kSecReturnRef] = true
            var result: CFTypeRef?
            try check(SecItemCopyMatching(query as CFDictionary, &result))
            guard let result, CFGetTypeID(result) == SecKeychainItemGetTypeID() else { throw SecretStoreError.unavailable }
            return unsafeDowncast(result, to: SecKeychainItem.self)
        }

        /// SecTrustedApplicationCopyData exposes a path, not a comparable designated requirement.
        /// The noninteractive data read is the enforcement check performed by Security's ACL engine.
        /// Enumeration detects legacy any-application/multiple-application ACLs; it cannot prove DR equality.
        @available(macOS, deprecated: 26.0, message: "Legacy System-keychain ACL API")
        private static func hasLegacyACL(_ keychain: SecKeychain) throws -> Bool {
            let item = try existingItem(keychain)
            var access: SecAccess?
            try check(SecKeychainItemCopyAccess(item, &access))
            guard let access else { throw SecretStoreError.unavailable }
            var list: CFArray?
            try check(SecAccessCopyACLList(access, &list))
            guard let acls = list as? [SecACL] else { throw SecretStoreError.unavailable }
            var found = false
            for acl in acls {
                let authorisations = SecACLCopyAuthorizations(acl) as NSArray
                guard authorisations.contains(kSecACLAuthorizationDecrypt) || authorisations.contains(kSecACLAuthorizationAny)
                else { continue }
                var applications: CFArray?; var description: CFString?; var prompt = SecKeychainPromptSelector()
                try check(SecACLCopyContents(acl, &applications, &description, &prompt))
                guard let trusted = applications as? [SecTrustedApplication], trusted.count == 1 else { return true }
                found = true
            }
            return !found
        }
    }
#endif
