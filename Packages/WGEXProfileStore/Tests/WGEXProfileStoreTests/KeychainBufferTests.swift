// SPDX-License-Identifier: MIT
import CoreFoundation
import Foundation
import Testing
import WGEXCore
@testable import WGEXProfileStore

private struct KeychainBufferTests {
    @Test
    func `SecItem input borrows the SecretBytes allocation without a Data copy`() throws {
        var fixture = try Data(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Tests/Fixtures/keys/client1.key"))
        let secret = try SecretBytes(wiping: &fixture)
        try KeychainSecretStore.withData(secret) { data in
            let same = secret.withUnsafeBytes { raw in
                CFDataGetBytePtr(data) == raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    && CFDataGetLength(data) == raw.count
            }
            #expect(same)
        }
    }
}
