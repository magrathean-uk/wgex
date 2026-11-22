// SPDX-License-Identifier: MIT
import Foundation
import Testing

#if os(macOS)
    private final class ConformanceBuildLocator {}
#endif

private struct SecretConformanceTests {
    #if os(macOS)
        @Test
        func `secret types fail compiler constraints for copying printing and coding`() throws {
            let build = Bundle(for: ConformanceBuildLocator.self).bundleURL.deletingLastPathComponent()
            let modules = build.appendingPathComponent("Modules")
            let moduleDirectory = FileManager.default.fileExists(atPath: modules.path) ? modules : build
            let (status, output) = try runCheck(moduleDirectory: moduleDirectory)
            #expect(status == 0, Comment(rawValue: String(decoding: output, as: UTF8.self)))
        }

        @Test
        func `compiler conformance checks fail loudly when the supplied module is missing`() throws {
            let build = Bundle(for: ConformanceBuildLocator.self).bundleURL.deletingLastPathComponent()
            let missing = build.appendingPathComponent("missing-module-\(UUID().uuidString)")
            let (status, output) = try runCheck(moduleDirectory: missing)
            #expect(status != 0)
            #expect(String(decoding: output, as: UTF8.self).contains("WGEXCore module missing from supplied build directory"))
        }

        private func runCheck(moduleDirectory: URL) throws -> (Int32, Data) {
            let package = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/bash")
            process.arguments = [
                package.appendingPathComponent("Tests/CompileChecks/check-secret-conformances.sh").path,
                moduleDirectory.path,
                moduleDirectory.deletingLastPathComponent().appendingPathComponent("secret-conformance-module-cache").path,
            ]
            let output = Pipe()
            process.standardOutput = output; process.standardError = output
            try process.run()
            let result = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (process.terminationStatus, result)
        }
    #endif
}
