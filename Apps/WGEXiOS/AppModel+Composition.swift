// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import SwiftUI
import WGEXAppComposition
import WGEXCore
import WGEXDiagnostics
import WGEXNEClient
import WGEXProfileStore
#if DEBUG || WGEX_LAB_BUILD
    import WGEXTesting
#endif

internal extension AppModel {
    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
            true
        #else
            false
        #endif
    }

    static let simulatorUnavailableMessage = "VPN unavailable on the simulator."

    convenience init(
        arguments: [String] = ProcessInfo.processInfo.arguments,
        simulator: Bool = AppModel.isSimulator,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        container: URL? = nil,
    ) {
        self.init(composition: IOSAppComposition(
            arguments: arguments, simulator: simulator, environment: environment, container: container,
        ))
    }

    var backendMessage: String {
        #if DEBUG
            if usesFakeBackend {
                return "Simulator / fake backend. No VPN configuration is installed."
            }
        #endif
        return if vpnUnavailableOnSimulator {
            Self.simulatorUnavailableMessage
        } else {
            "Backend not wired. Protection is unknown."
        }
    }
}

@MainActor
internal struct IOSAppComposition {
    internal let usesFakeBackend: Bool
    /// The real path on a simulator: Network Extension does not run there, so there is no backend and no VPN.
    internal let vpnUnavailableOnSimulator: Bool
    internal let appearanceOverride: ColorScheme?
    internal let backend: any TunnelBackend?
    internal let secrets: any SecretStore
    /// The real path seals keys to `.keychain(persistentRef)`; fake sessions retain SecretID references.
    internal let secretComposition: ProfileComposition
    internal let container: URL
    internal let logFile: SharedLogFile
    #if DEBUG || WGEX_LAB_BUILD
        internal let scenario: FakeScenario?
    #endif

    /// Fakes are used only when asked (`-WGEXFakeBackend`, or `WGEX_HOSTED_TESTS=1` for the hosted test host); every
    /// other launch composes the real Network Extension client and Keychain, on the simulator too.
    internal init(arguments: [String], simulator: Bool, environment: [String: String] = [:], container: URL?) {
        #if DEBUG || WGEX_LAB_BUILD
            let fake = arguments.contains("-WGEXFakeBackend") || environment["WGEX_HOSTED_TESTS"] == "1"
        #else
            let fake = false
        #endif
        let resolvedContainer = container ?? Self.defaultContainer(fake: fake)
        usesFakeBackend = fake
        vpnUnavailableOnSimulator = !fake && simulator
        self.container = resolvedContainer
        logFile = Self.makeLogFile(container: resolvedContainer)
        #if DEBUG || WGEX_LAB_BUILD
            appearanceOverride = Self.appearance(arguments: arguments, enabled: fake)
            if fake {
                backend = FakeTunnelBackend(capabilities: [.allowLAN])
                let memory = InMemorySecretStore()
                secrets = memory
                secretComposition = ProfileComposition(strategy: .identities(memory))
                scenario = FakeScenario.parse(arguments: arguments)
                return
            }
            scenario = nil
        #else
            appearanceOverride = nil
        #endif
        let keychain = KeychainSecretStore()
        let bridge = ProfileComposition(strategy: .persistentReferences(keychain))
        secrets = keychain
        secretComposition = bridge
        if simulator {
            backend = nil
        } else {
            backend = NEManagerClient(
                system: NetworkExtensionManagerSystem(),
                platform: .iOS,
                purgeSecrets: Self.purge(container: resolvedContainer, bridge: bridge),
            )
        }
    }

    /// The real path with injected seams, for tests that must not touch the Keychain or Network Extension.
    internal init(
        container: URL, keychain: any PersistentReferenceSecretStore, backend: any TunnelBackend?, simulator: Bool = false,
    ) {
        usesFakeBackend = false
        vpnUnavailableOnSimulator = simulator
        appearanceOverride = nil
        self.backend = backend
        secrets = keychain
        secretComposition = ProfileComposition(strategy: .persistentReferences(keychain))
        self.container = container
        logFile = Self.makeLogFile(container: container)
        #if DEBUG || WGEX_LAB_BUILD
            scenario = nil
        #endif
    }

    private static func makeLogFile(container: URL) -> SharedLogFile {
        // Real App Group containers already exist; isolated test and fake containers may not yet have been created.
        try? FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
        return SharedLogFile(directory: container)
    }

    private static func defaultContainer(fake: Bool) -> URL {
        if fake {
            FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-fake-\(UUID().uuidString)", isDirectory: true)
        } else {
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: BuildIdentifiers.current.appGroup)
                ?? FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-unavailable", isDirectory: true)
        }
    }

    /// The backend's secret purge: reads the profile (still stored when `remove` runs) and deletes its Keychain items.
    private static func purge(container: URL, bridge: ProfileComposition) -> @Sendable (UUID) async throws -> Void {
        let store = ProfileStore(container: container)
        return { id in
            let profile: TunnelProfile
            do { profile = try await store.load(id) }
            catch ProfileStoreError.notFound { return }
            try await bridge.deleteSecrets(of: profile)
        }
    }

    #if DEBUG || WGEX_LAB_BUILD
        private static func appearance(arguments: [String], enabled: Bool) -> ColorScheme? {
            guard enabled, let index = arguments.firstIndex(of: "-WGEXAppearance"),
                  arguments.indices.contains(index + 1) else { return nil }
            switch arguments[index + 1] { case "light": return .light
            case "dark": return .dark
            default: return nil }
        }
    #endif
}
