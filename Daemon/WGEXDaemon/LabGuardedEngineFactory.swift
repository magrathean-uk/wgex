// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    import WGEXCore
    import WGEXDaemonCore
    import WGEXDaemonProtocol
    import WGEXEngineInterface

    /// Lab-only guard wrapper around the same production engine composition.
    public struct LabGuardedEngineFactory: DaemonEngineCreating {
        /// Creates an inert guard wrapper.
        public init() {}

        /// Refuses engine creation unless all three lab guard conditions hold.
        public func create(configuration: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine {
            guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            return try await SystemDaemonEngineFactory(logLevel: .debug).create(configuration: configuration, generation: generation)
        }
    }
#endif
