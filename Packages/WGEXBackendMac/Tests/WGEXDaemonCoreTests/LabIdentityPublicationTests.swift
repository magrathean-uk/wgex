// SPDX-License-Identifier: MIT
#if os(macOS)
    import Darwin
    import Foundation
    import Testing
    @testable import WGEXDaemonCore

    /// DEC-013: the daemon publishes its own code-directory hashes, and secure install measures the installed app and
    /// daemon at each check, in Lab builds only. This test image links the
    /// daemon core statically, so it holds exactly what a build of this flavour compiles; the markers are joined
    /// at run time so this file does not supply them itself.
    private struct LabIdentityPublicationTests {
        @Test
        func `the daemon publishes its identity in Lab builds only`() throws {
            var info = Dl_info()
            try #require(dladdr(#dsohandle, &info) != 0)
            let image = try Data(contentsOf: URL(fileURLWithPath: String(cString: info.dli_fname)), options: .mappedIfSafe)
            #if WGEX_LAB_BUILD
                let compiled = true
                #expect(DaemonRuntimeMessage.labIdentityUnpublished.rawValue.hasPrefix("Lab daemon identity was not published"))
            #else
                let compiled = false
            #endif
            let markers = [
                ["Lab daemon identity", " was not published"], ["LabDaemon", "IdentityFile"], ["LabRunning", "Code"],
                ["LabInstalled", "Identity"],
            ].map { $0.joined() }
            for marker in markers {
                #expect((image.range(of: Data(marker.utf8)) != nil) == compiled, "\(marker)")
            }
        }
    }
#endif
