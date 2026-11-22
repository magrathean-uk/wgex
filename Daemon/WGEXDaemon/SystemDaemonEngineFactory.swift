// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngine
import WGEXEngineInterface

/// Associates the production engine with the identity used for ownership checks: the utun's name and index and this
/// process's descriptor for it, recorded for the generation (M1-18).
public struct SystemDaemonEngineFactory: DaemonEngineCreating {
    private let makeEngine: @Sendable (EngineConfiguration) throws -> any EngineControlling
    private let logLevel: EngineConfiguration.LogLevel
    private let descriptors: TunnelDescriptorTable
    private let identities: any InterfaceIdentityReading

    /// Creates an inert factory; debug logging is accepted only in Lab builds, after binding validation.
    public init(logLevel: EngineConfiguration.LogLevel = .info) {
        self.init(logLevel: logLevel, makeEngine: { try GoEngineFactory(logLevel: $0.logLevel).create(configuration: $0) })
    }

    /// Test seam: injection guarantees a guard regression cannot create a host tunnel.
    internal init(
        logLevel: EngineConfiguration.LogLevel = .info,
        descriptors: TunnelDescriptorTable = .process,
        identities: any InterfaceIdentityReading? = nil,
        makeEngine: @escaping @Sendable (EngineConfiguration) throws -> any EngineControlling,
    ) {
        #if WGEX_LAB_BUILD
            self.logLevel = logLevel
        #else
            self.logLevel = .info
        #endif
        self.makeEngine = makeEngine
        self.descriptors = descriptors
        self.identities = identities ?? SystemInterfaceIdentity(descriptors: descriptors)
    }

    /// Reads the created tunnel's identity before the controller can configure addresses.
    public func create(configuration: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine {
        guard let v4 = configuration.bindInterfaceIndexV4, let v6 = configuration.bindInterfaceIndexV6,
              v4 > 0, v6 > 0 else { throw DaemonFailure.hostUnboundInterfaces }
        var configuration = configuration
        configuration.logLevel = logLevel
        let engine = try makeEngine(configuration)
        do {
            // The Go engine fixes its utun name at construction, so a nil here is not a late statistic (M1-17 D12).
            guard let name = try await engine.statistics().interfaceName else { throw Self.refused(.engineInterfaceMissing) }
            // The engine created the utun in this process and holds its descriptor until shutdown (M1-18).
            guard let descriptor = descriptors.register(name: name, generation: generation) else {
                throw Self.refused(.tunnelDescriptorMissing)
            }
            guard let identity = try await identities.identity(named: name), identity.descriptor == descriptor else {
                throw Self.refused(.tunnelIdentityMissing)
            }
            return CreatedDaemonEngine(engine: engine, identity: identity)
        } catch { await engine.shutdown(); throw error }
    }

    private static func refused(_ event: DaemonDiagnostics.OwnershipEvent) -> DaemonPortError {
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.ownership(event)
        #endif
        return .notOwned
    }
}
