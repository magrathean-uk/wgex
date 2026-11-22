// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// Secure install may create a missing wrapping key; boot may only read it.
public protocol DaemonKeyProvisioning: DaemonKeyProvider {
    /// Creates a missing key and verifies a noninteractive read. Existing keys are never rotated.
    func provision() throws
}

/// Existing key access could not be repaired or verified; key bytes are never replaced.
/// Testable provisioning transaction. The platform port owns noninteractive lookup and the daemon-only ACL.
public struct WrappingKeyProvisioner: DaemonKeyProvisioning {
    private let read: @Sendable () throws -> SecretBytes
    private let create: @Sendable (borrowing SecretBytes) throws -> Void
    private let generate: @Sendable () throws -> SecretBytes
    private let legacyAccess: @Sendable () throws -> Bool
    private let repairAccess: @Sendable () throws -> Void
    private let hasEncryptedState: @Sendable () throws -> Bool

    /// Callbacks borrow secret memory and must not retain a plaintext copy.
    public init(
        read: @escaping @Sendable () throws -> SecretBytes,
        create: @escaping @Sendable (borrowing SecretBytes) throws -> Void,
        generate: @escaping @Sendable () throws -> SecretBytes,
        repairAccess: @escaping @Sendable () throws -> Void = {},
        legacyAccess: @escaping @Sendable () throws -> Bool = { false },
        hasEncryptedState: @escaping @Sendable () throws -> Bool = { false },
    ) {
        self.read = read; self.create = create; self.generate = generate; self.hasEncryptedState = hasEncryptedState
        self.repairAccess = repairAccess; self.legacyAccess = legacyAccess
    }

    /// Read-only boot path; a missing, locked or malformed key fails closed.
    public func wrappingKey() throws -> SecretBytes {
        let key = try read()
        guard key.count == 32 else { throw SecretStoreError.unavailable }
        return key
    }

    /// A failed read other than not-found never authorises replacement.
    public func provision() throws {
        if try existingKeyIsReady() {
            return
        }
        guard try !hasEncryptedState() else { throw SecretStoreError.unavailable }
        let generated = try generate()
        guard generated.count == 32 else { throw SecretStoreError.unavailable }
        do { try create(generated) }
        catch SecretStoreError.duplicate {
            // Another provisioner won the race. Keep its key; never overwrite it.
            _ = try wrappingKey(); return
        }
        let loaded = try wrappingKey()
        guard generated.constantTimeEquals(loaded) else { throw SecretStoreError.unavailable }
    }

    private func existingKeyIsReady() throws -> Bool {
        let key: SecretBytes
        do { key = try wrappingKey() }
        catch SecretStoreError.notFound { return false }
        catch { _ = try repairExistingKey(); return true }
        if try legacyAccess() {
            let repaired = try repairExistingKey()
            guard key.constantTimeEquals(repaired) else { throw DaemonFailure.keyAccessRepairFailed }
        }
        return true
    }

    private func repairExistingKey() throws -> SecretBytes {
        do {
            try repairAccess()
            let key = try wrappingKey()
            guard try !legacyAccess() else { throw DaemonFailure.keyAccessRepairFailed }
            return key
        } catch { throw DaemonFailure.keyAccessRepairFailed }
    }
}

/// Accepts readable legacy ACLs without risking a key that protects existing ciphertext.
public struct WrappingKeyReadPolicy: DaemonKeyProvider {
    private let read: @Sendable () throws -> SecretBytes
    private let legacyAccess: @Sendable () throws -> Bool
    private let warnLegacy: @Sendable () -> Void

    /// The platform read is noninteractive; ACL inspection reports legacy breadth only.
    public init(
        read: @escaping @Sendable () throws -> SecretBytes,
        legacyAccess: @escaping @Sendable () throws -> Bool,
        warnLegacy: @escaping @Sendable () -> Void,
    ) {
        self.read = read; self.legacyAccess = legacyAccess; self.warnLegacy = warnLegacy
    }

    /// ACL repair is a separate owner-authorised operation and never changes key bytes.
    public func wrappingKey() throws -> SecretBytes {
        let key = try read()
        guard key.count == 32 else { throw SecretStoreError.unavailable }
        if try legacyAccess() {
            warnLegacy()
        }
        return key
    }
}
