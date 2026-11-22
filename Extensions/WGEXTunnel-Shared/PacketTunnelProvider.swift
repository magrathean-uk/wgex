// SPDX-License-Identifier: MIT

import Foundation
import NetworkExtension
import WGEXCore
import WGEXDiagnostics
import WGEXEngine
import WGEXNEProvider

/// Thin extension shell, compiled once into both the iOS and the tvOS extension targets (the platform is a compile-time
/// constant below). It is never launched by host tests.
@MainActor
// Safety: NE owns concurrent callbacks; our sole stored property is an immutable
// MainActor reference. All access to inherited mutable NE state stays on MainActor.
// Remove the unchecked bridge when the SDK gives NEPacketTunnelProvider Sendable conformance.
public final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let state = ProviderShellState()

    override public nonisolated func startTunnel(options: [String: NSObject]?) async throws {
        let optionID = options?["profileID"] as? String
        let rawID = await state.profileID(provider: self, optionID: optionID)
        guard let rawID, let id = UUID(uuidString: rawID) else { throw NEVPNError(.configurationInvalid) }
        let controller = try await state.controller(provider: self)
        try await controller.startTunnel(profileID: id)
    }

    override public nonisolated func stopTunnel(with reason: NEProviderStopReason) async {
        await state.current?.stopTunnel(reason: reason.rawValue)
    }

    override public nonisolated func sleep() async {
        await state.current?.sleep()
    }

    override public nonisolated func wake() {
        let state = state
        Task { try? await state.current?.wake() }
    }

    override public nonisolated func handleAppMessage(_ messageData: Data) async -> Data? {
        await state.current?.handle(messageData)
    }
}

/// Serialises lazy construction; Foundation/NE objects remain on MainActor.
@MainActor
private final class ProviderShellState {
    #if os(tvOS)
        static let platform = ProfilePlatform.tvOS
    #else
        static let platform = ProfilePlatform.iOS
    #endif

    private(set) var current: ProviderController?
    func profileID(provider: NEPacketTunnelProvider, optionID: String?) -> String? {
        optionID ?? (provider.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profileID"] as? String
    }

    func controller(provider: NEPacketTunnelProvider) throws -> ProviderController {
        if let current {
            return current
        }
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: BuildIdentifiers.current.appGroup)
        else {
            throw NEVPNError(.configurationInvalid)
        }
        let controller = ProviderController(
            system: NetworkExtensionProviderSystem(provider: provider, descriptorFinder: { EngineLinkage.findUTunDescriptor() }),
            profiles: AppGroupProfileLoader(container: container), secrets: PersistentReferenceSecretLoader(),
            resolver: PhysicalEndpointResolver(), platform: ProviderShellState.platform,
            engineFactory: { try EngineActor(configuration: $0) },
            logSink: SharedProviderLogSink(file: SharedLogFile(directory: container)),
        )
        current = controller
        return controller
    }
}

/// ProviderController supplies fixed lifecycle text and scrubbed engine messages; the file redacts again before writing.
private nonisolated struct SharedProviderLogSink: ProviderLogSink {
    let file: SharedLogFile

    func write(_ line: String) {
        file.append(line, process: .tunnel)
    }
}
