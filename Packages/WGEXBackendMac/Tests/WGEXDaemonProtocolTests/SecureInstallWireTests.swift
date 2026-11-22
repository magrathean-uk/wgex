// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXDaemonProtocol

private struct SecureInstallWireTests {
    private static let statusBytes = "YnBsaXN0MDDRAQJfEBNzZWN1cmVJbnN0YWxsU3RhdHVz0AgLIQAAAAAAAAEBAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAi"
    private static let performBytes = "YnBsaXN0MDDRAQJfEBRwZXJmb3JtU2VjdXJlSW5zdGFsbNAICyIAAAAAAAABAQAAAAAAAAADAAAAAAAAAAAAAAAAAAAAIw=="
    private static let reportBytes = "YnBsaXN0MDDRAQJdc2VjdXJlSW5zdGFsbNEDBFJfMNcFBgcICQoLDA0MDg8PEF5idW5kbGVJZGVudGl0eVpidW5kbGVQYXRoXmRhZW1vbklkZW50aXR5XxATaXNVbmRlckFwcGxpY2F0aW9uc18QE25vblJvb3RPd25lZEVudHJpZXNfEBZub25Sb290V3JpdGFibGVFbnRyaWVzVXN0YXRlV21hdGNoZWRfEBYvQXBwbGljYXRpb25zL1dHRVguYXBwCRAA0RESWHZlcmlmaWVk0AgLGRwfLj1IV22DnKKqw8TGydIAAAAAAAABAQAAAAAAAAATAAAAAAAAAAAAAAAAAAAA0w=="

    @Test
    func `secure install requests and report match fixed binary plist goldens`() throws {
        try compare(Self.statusBytes, value: Request.secureInstallStatus)
        try compare(Self.performBytes, value: Request.performSecureInstall)
        try compare(Self.reportBytes, value: Reply.secureInstall(SecureInstallReport(
            state: .verified, bundlePath: "/Applications/WGEX.app", isUnderApplications: true,
            bundleIdentity: .matched, daemonIdentity: .matched,
        )))
    }

    private func compare<Value: Codable & Equatable>(_ base64: String, value: Value) throws {
        let golden = try #require(Data(base64Encoded: base64))
        #expect(try WireCodec.decode(Value.self, from: golden) == value)
        let encoded = try WireCodec.encode(value)
        let expectedShape = try #require(PropertyListSerialization.propertyList(from: golden, format: nil) as? NSDictionary)
        let actualShape = try #require(PropertyListSerialization.propertyList(from: encoded, format: nil) as? NSDictionary)
        #expect(actualShape == expectedShape)
    }

    @Test(arguments: SecureInstallReport.Reason.allCases)
    func `attention reasons and counts round trip`(_ reason: SecureInstallReport.Reason) throws {
        let report = SecureInstallReport(
            state: .needsAttention(reason),
            bundlePath: "/Applications/WGEX.app",
            nonRootOwnedEntries: 7,
            nonRootWritableEntries: 1,
            isUnderApplications: true,
            bundleIdentity: .failed,
            daemonIdentity: .unavailable,
        )
        #expect(try WireCodec.decode(Reply.self, from: WireCodec.encode(Reply.secureInstall(report))) == .secureInstall(report))
        var progress = report; progress.state = .inProgress
        #expect(try WireCodec.decode(SecureInstallReport.self, from: WireCodec.encode(progress)) == progress)
    }
}
