// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
@testable import WGEXDaemonCore

package struct ControllerSecretSpy: TunnelSecretStoring {
    package let base: any TunnelSecretStoring
    package let trace: HostTrace
    package func saveBundle(_ bytes: consuming SecretBytes, profileID: UUID) async throws {
        try await base.saveBundle(bytes, profileID: profileID)
    }

    package func loadBundle(profileID: UUID) async throws -> SecretBytes {
        try await base.loadBundle(profileID: profileID)
    }

    package func deleteBundle(profileID: UUID) async throws {
        try trace.record("secrets.delete")
        try await base.deleteBundle(profileID: profileID)
    }

    package func storedBundleProfileIDs() async throws -> [UUID] {
        try await base.storedBundleProfileIDs()
    }

    package func removeAllSecrets() async throws {
        try trace.record("secrets.removeAll")
        try await base.removeAllSecrets()
    }

    package func removeAllBundles() async throws {
        try trace.record("bundles.removeAll")
        try await base.removeAllBundles()
    }

    package func removeWrappingKey() async throws {
        try trace.record("key.remove")
        try await base.removeWrappingKey()
    }
}
