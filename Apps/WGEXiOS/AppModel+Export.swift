// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import WGEXAppComposition
import WGEXCore
import WGEXUI

internal extension AppModel {
    /// The bundled provider uses this pinned wireguard-go revision (Engine/go/engine/engine.go).
    var engineVersion: String {
        "b3bc704ef0ee"
    }

    /// Keys are loaded one tunnel at a time, only on the explicit export action, and never stored in view state.
    func exportArchive() async throws -> URL {
        guard !isBusy else { throw IOSTunnelArchive.Failure.writeFailed }
        let snapshot = profiles
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-export-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700],
            )
            return try await IOSTunnelArchive
                .write(names: snapshot.map(\.name), to: directory.appendingPathComponent("WireGuard.zip")) { index in
                    let packed = try await self.secretComposition.load(snapshot[index])
                    let export = ExportModel(profile: snapshot[index], secrets: packed)
                    export.request(.file)
                    export.confirm()
                    return try export.confirmedFileText()
                }
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }
}
