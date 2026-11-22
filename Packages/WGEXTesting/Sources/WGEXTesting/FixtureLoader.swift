// SPDX-License-Identifier: MIT

import Foundation

/// Loads files from the repository's `Tests/Fixtures` directory.
public struct FixtureLoader: Sendable {
    /// Failures locating or reading a fixture.
    public enum LoadError: Error, Sendable, Hashable {
        /// No `Tests/Fixtures` directory above the calling file.
        case rootNotFound
        /// The path escapes the fixtures directory.
        case outsideFixtures(String)
        /// The fixture does not exist or cannot be read.
        case notFound(String)
    }

    /// The fixtures directory.
    public let root: URL

    /// Uses an explicit fixtures directory.
    public init(root: URL) {
        self.root = root.standardizedFileURL
    }

    /// Finds `Tests/Fixtures` by walking up from the calling source file.
    public static func repository(file: StaticString = #filePath) throws(LoadError) -> FixtureLoader {
        var directory = URL(fileURLWithPath: "\(file)").deletingLastPathComponent()
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent("Tests/Fixtures", isDirectory: true)
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory), isDirectory.boolValue {
                return FixtureLoader(root: candidate)
            }
            directory.deleteLastPathComponent()
        }
        throw .rootNotFound
    }

    /// URL of `relativePath`; refuses paths that leave the fixtures directory.
    public func url(_ relativePath: String) throws(LoadError) -> URL {
        let resolved = root.appendingPathComponent(relativePath).standardizedFileURL
        guard resolved.path.hasPrefix(root.path + "/") else {
            throw .outsideFixtures(relativePath)
        }
        return resolved
    }

    /// Contents of `relativePath`.
    public func data(_ relativePath: String) throws(LoadError) -> Data {
        let location = try url(relativePath)
        guard let data = FileManager.default.contents(atPath: location.path) else {
            throw .notFound(relativePath)
        }
        return data
    }

    /// UTF-8 text of `relativePath`.
    public func text(_ relativePath: String) throws(LoadError) -> String {
        guard let text = try String(bytes: data(relativePath), encoding: .utf8) else {
            throw .notFound(relativePath)
        }
        return text
    }
}
