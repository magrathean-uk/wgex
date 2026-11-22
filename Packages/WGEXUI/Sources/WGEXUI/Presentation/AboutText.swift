// SPDX-License-Identifier: MIT

// No platform guard: the Mac and the iPhone and iPad About pages show the same version line (SPEC 8.5, 10).
import Foundation

package nonisolated enum AboutText {
    /// "Version 1.2 (45)", or the Development fallback when the bundle has no version.
    package static func versionLine(_ info: [String: Any]?) -> String {
        let version = (info?["CFBundleShortVersionString"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? MacStrings.versionDevelopment
        guard let build = (info?["CFBundleVersion"] as? String).flatMap({ $0.isEmpty ? nil : $0 }) else {
            return MacStrings.version + version
        }
        return MacStrings.versionWithBuild(version, build)
    }
}
