// SPDX-License-Identifier: MIT

import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXProfileStore

private struct WrappingKeyRepairOrderTests {
    @Test func `healthy restricted key never attempts an access mutation`() throws {
        let trace = Mutex<[String]>([])
        let seam = WrappingKeyProvisioner(
            read: {
                trace.withLock { $0.append("read") }; return try ControllerHarness.testKey()
            },
            create: { _ in Issue.record("Must retain existing key") },
            generate: { try ControllerHarness.testKey() },
            repairAccess: { trace.withLock { $0.append("repair") }; throw HostTestError.injected },
            legacyAccess: {
                trace.withLock { $0.append("acl") }; return false
            },
        )
        try seam.provision()
        #expect(trace.withLock { $0 } == ["read", "acl"])
    }

    @Test(arguments: [false, true])
    func `legacy or unreadable key is repaired only after the initial read`(legacy: Bool) throws {
        let trace = Mutex<[String]>([]), repaired = Mutex(false)
        let seam = WrappingKeyProvisioner(read: {
            trace.withLock { $0.append("read") }
            if !legacy, !repaired.withLock({ $0 }) {
                throw SecretStoreError.locked
            }
            return try ControllerHarness.testKey()
        }, create: { _ in Issue.record("Must retain existing key") }, generate: { try ControllerHarness.testKey() }, repairAccess: {
            trace.withLock { $0.append("repair") }; repaired.withLock { $0 = true }
        }, legacyAccess: {
            trace.withLock { $0.append("acl") }; return legacy && !repaired.withLock { $0 }
        })
        try seam.provision()
        #expect(trace.withLock { $0 } == (legacy ? ["read", "acl", "repair", "read", "acl"] : ["read", "repair", "read", "acl"]))
    }

    @Test func `repair failure is distinct and survives status on a readable key`() async {
        let installer = SecureInstall(system: FakeSecureInstallSystem(), provisionKey: {
            throw DaemonFailure.keyAccessRepairFailed
        }, validateKey: { let key = try ControllerHarness.testKey(); _ = key.count })
        #expect(await installer.perform().state == .needsAttention(.wrappingKeyRepairFailed))
        #expect(await installer.status().state == .needsAttention(.wrappingKeyRepairFailed))
        await installer.invalidate()
        #expect(await installer.status().state == .verified)
    }

    @Test func `legacy ACL mutation failure is reported after the initial read`() throws {
        let trace = Mutex<[String]>([])
        let seam = WrappingKeyProvisioner(read: {
            trace.withLock { $0.append("read") }; return try ControllerHarness.testKey()
        }, create: { _ in Issue.record("Must retain existing key") }, generate: { try ControllerHarness.testKey() }, repairAccess: {
            trace.withLock { $0.append("repair") }; throw SecretStoreError.locked
        }, legacyAccess: { trace.withLock { $0.append("acl") }; return true })
        #expect(throws: DaemonFailure.keyAccessRepairFailed) { try seam.provision() }
        #expect(trace.withLock { $0 } == ["read", "acl", "repair"])
    }

    @Test func `missing keys are created without ACL repair`() throws {
        let present = Mutex(false), repaired = Mutex(false)
        let seam = WrappingKeyProvisioner(
            read: {
                guard present.withLock({ $0 }) else { throw SecretStoreError.notFound }
                return try ControllerHarness.testKey()
            },
            create: { _ in present.withLock { $0 = true } },
            generate: { try ControllerHarness.testKey() },
            repairAccess: { repaired.withLock { $0 = true } },
        )
        try seam.provision()
        #expect(!repaired.withLock { $0 })
    }
}
