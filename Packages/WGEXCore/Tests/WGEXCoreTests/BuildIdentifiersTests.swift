// SPDX-License-Identifier: MIT

import Testing
import WGEXCore

private struct BuildIdentifiersTests {
    @Test
    func `fallback uses the development base`() {
        if !BuildIdentifiers.isGenerated {
            #expect(BuildIdentifiers.current.base == "com.magrathean.WGEXApp.dev")
        }
        if BuildIdentifiers.isGenerated {
            // The generated file carries the maintainer's own team from Config/Local.xcconfig.
            #expect(BuildIdentifiers.current.team.count == 10)
        } else {
            #expect(BuildIdentifiers.current.team == "ABCDE12345")
        }
    }

    @Test
    func `identifiers derive from the base`() {
        let ids = BuildIdentifiers(base: "com.example.App", team: "TEAM")
        #expect(ids.app == "com.example.App")
        #expect(ids.tunnelExtension == "com.example.App.tunnel")
        #expect(ids.liveActivityExtension == "com.example.App.liveactivity")
        #expect(ids.daemonService == "com.example.App.daemon")
        #expect(ids.cli == "com.example.App.cli")
        #expect(ids.appGroup == "group.com.example.App")
        #expect(ids.keychainAccessGroup == "TEAM.com.example.App")
        #expect(ids.daemonPlistName == "com.example.App.daemon.plist")
    }

    @Test
    func `variants add and remove the development suffix`() {
        let dev = BuildIdentifiers(base: "com.example.App.dev", team: "TEAM")
        #expect(dev.isDevelopment)
        #expect(dev.releaseVariant.base == "com.example.App")
        #expect(!dev.releaseVariant.isDevelopment)
        #expect(dev.releaseVariant.developmentVariant == dev)
        #expect(dev.developmentVariant == dev)
    }

    @Test
    func `static accessors mirror current`() {
        #expect(BuildIdentifiers.base == BuildIdentifiers.current.base)
        #expect(BuildIdentifiers.daemonService == BuildIdentifiers.current.daemonService)
        #expect(BuildIdentifiers.tunnelExtension == BuildIdentifiers.current.tunnelExtension)
    }
}
