// SPDX-License-Identifier: MIT

#if WGEX_ENGINE_TEST_SUPPORT
    import CWGEXEngineTest
#else
    import CWGEXEngine
#endif
import Foundation

/// The implementation linked into this process.
public enum EngineLinkage: Sendable {
    /// Retained for source compatibility with callers built before engine integration.
    case none
    /// The Go engine from the packaged XCFramework.
    case goEngine

    public static let current = EngineLinkage.goEngine

    /// Finds an existing NetworkExtension utun descriptor; never creates an interface.
    public static func findUTunDescriptor() -> Int32 {
        wgex_find_utun_fd()
    }

    /// Embedded provenance; its script digest matches Binary/provenance.json.
    public static var provenance: [String: String] {
        // The ABI owns this immutable NUL-terminated string for the process lifetime.
        let json = unsafe String(cString: wgex_build_info())
        return (try? JSONDecoder().decode([String: String].self, from: Data(json.utf8))) ?? [:]
    }
}
