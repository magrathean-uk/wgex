// SPDX-License-Identifier: MIT
import WGEXEngineInterface

/// Production Go engine construction, independent of any daemon or lab environment.
public struct GoEngineFactory: Sendable {
    private let logLevel: EngineConfiguration.LogLevel
    /// Creates an inert factory with debug logging disabled unless explicitly requested by the Lab composition.
    public init(logLevel: EngineConfiguration.LogLevel = .info) {
        self.logLevel = logLevel
    }

    /// Creates an engine that owns its tunnel and callback lifetime.
    public func create(configuration: EngineConfiguration) throws -> EngineActor {
        var configuration = configuration
        configuration.logLevel = logLevel
        return try EngineActor(configuration: configuration)
    }
}
