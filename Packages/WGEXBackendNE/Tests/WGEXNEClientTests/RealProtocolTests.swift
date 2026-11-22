// SPDX-License-Identifier: MIT

#if os(iOS) || os(tvOS)
    import NetworkExtension
    import Testing
    import WGEXCore
    import WGEXNEClient

    private struct RealProtocolTests {
        /// Construction only; never save preferences or start a tunnel.
        @Test(arguments: [0, 1, 2, 4, 8, 16, 31, 21, 10])
        @MainActor func `builder flags reach the real NE protocol independently`(_ pattern: Int) throws {
            var profile = try GoldenFixture.profile("flags-mixed")
            profile.protection.ios = IOSProtection(
                includeAllNetworks: pattern & 1 != 0, excludeLocalNetworks: pattern & 2 != 0,
                excludeCellularServices: pattern & 4 != 0, excludeAPNs: pattern & 8 != 0,
                excludeDeviceCommunication: pattern & 16 != 0,
            )
            #if os(iOS)
                let platform = ProfilePlatform.iOS
            #else
                let platform = ProfilePlatform.tvOS
            #endif
            let value = ProtocolConfigurationBuilder.build(
                profile, platform: platform, identifiers: BuildIdentifiers(base: "test.wgex", team: "TEST"),
            )
            let proto = try NetworkExtensionManagerSystem.makeProtocol(value)
            #expect(proto.providerBundleIdentifier == value.providerBundleIdentifier)
            #expect(proto.providerBundleIdentifier == "test.wgex.tunnel")
            #if os(iOS)
                #expect(proto.includeAllNetworks == (pattern & 1 != 0))
                #expect(proto.excludeLocalNetworks == (pattern & 2 != 0))
                #expect(proto.excludeCellularServices == (pattern & 4 != 0))
                #expect(proto.excludeAPNs == (pattern & 8 != 0))
                #expect(proto.excludeDeviceCommunication == (pattern & 16 != 0))
            #else
                #expect(proto.enforceRoutes)
            #endif
        }
    }
#endif
