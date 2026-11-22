// SPDX-License-Identifier: MIT
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXProfileStore

private struct WrappingKeyProvisioningTests {
    @Test
    func `a missing key with retained encrypted state is never replaced`() throws {
        let creates = Mutex(0)
        let seam = WrappingKeyProvisioner(read: { throw SecretStoreError.notFound }, create: { _ in
            creates.withLock { $0 += 1 }
        }, generate: { try ControllerHarness.testKey() }, hasEncryptedState: { true })
        #expect(throws: SecretStoreError.unavailable) { try seam.provision() }
        #expect(creates.withLock { $0 } == 0)
    }

    @Test
    func `startup registration fails closed when encrypted bundles exist but their wrapping key is missing`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        try await harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: harness.profile.id)
        let missingKeyStore = try DaemonSecretStore(directory: harness.directory, keyProvider: MissingWrappingKey())
        let registry = try ProfileRegistry(
            repository: DirectoryProfileRepository(directory: harness.directory),
            secrets: missingKeyStore,
            bundles: missingKeyStore,
        )
        await #expect(throws: SecretStoreError.unavailable) { try await registry.registerInstalledProfiles() }
    }

    @Test
    func `secure install status refuses a wrapping key that cannot be read at boot`() async {
        let system = FakeSecureInstallSystem()
        let installer = SecureInstall(system: system, validateKey: { throw SecretStoreError.locked })
        #expect(await installer.status().state == .needsAttention(.wrappingKeyUnavailable))
    }

    @Test
    func `key provisioning is gated by verified secure install and failure prevents success`() async {
        let system = FakeSecureInstallSystem()
        let calls = Mutex(0)
        let installer = SecureInstall(system: system, provisionKey: {
            calls.withLock { $0 += 1 }; throw SecretStoreError.locked
        })
        #expect(await installer.perform().state == .needsAttention(.wrappingKeyUnavailable))
        #expect(calls.withLock { $0 } == 1)
        system.state.withLock { $0.identity.daemon = .failed; $0.entries[1].changeStamp = "changed" }
        #expect(await installer.perform().state == .needsAttention(.identityMismatch))
        #expect(calls.withLock { $0 } == 1)
    }

    @Test
    func `secure install provisions once and validates noninteractive boot retrieval`() throws {
        let exists = Mutex(false)
        let writes = Mutex(0)
        let seam = WrappingKeyProvisioner(read: {
            guard exists.withLock({ $0 }) else { throw SecretStoreError.notFound }
            return try ControllerHarness.testKey()
        }, create: { key in
            #expect(key.count == 32)
            writes.withLock { $0 += 1 }; exists.withLock { $0 = true }
        }, generate: { try ControllerHarness.testKey() })
        #expect(throws: SecretStoreError.notFound) { _ = try seam.wrappingKey() }
        try seam.provision()
        try seam.provision()
        let key = try seam.wrappingKey()
        #expect(key.count == 32)
        #expect(writes.withLock { $0 } == 1)
    }

    @Test
    func `locked or invalid existing keys are never replaced`() throws {
        let writes = Mutex(0)
        let seam = WrappingKeyProvisioner(read: { throw SecretStoreError.locked }, create: { _ in
            writes.withLock { $0 += 1 }
        }, generate: { try ControllerHarness.testKey() })
        #expect(throws: DaemonFailure.keyAccessRepairFailed) { try seam.provision() }
        #expect(writes.withLock { $0 } == 0)
    }
}

private struct MissingWrappingKey: DaemonKeyProvider {
    func wrappingKey() throws -> SecretBytes {
        throw SecretStoreError.notFound
    }
}
