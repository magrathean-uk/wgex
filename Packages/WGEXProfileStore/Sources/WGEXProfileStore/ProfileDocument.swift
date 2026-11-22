// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Independently versioned envelope; the contained Core profile retains its own schema version.
public struct ProfileDocument: Codable, Sendable, Hashable {
    public static let currentSchemaVersion = 3
    public var schemaVersion: Int
    public var profile: TunnelProfile

    public init(profile: TunnelProfile, schemaVersion: Int = Self.currentSchemaVersion) {
        self.schemaVersion = schemaVersion; self.profile = profile
    }

    public func encoded() throws -> Data {
        try DocumentCodec.encode(self)
    }
}

public struct AppSettings: Codable, Sendable, Hashable {
    public var selectedProfileID: UUID?
    public var featureFlags: FeatureFlags

    public init(selectedProfileID: UUID? = nil, featureFlags: FeatureFlags = .defaults) {
        self.selectedProfileID = selectedProfileID; self.featureFlags = featureFlags
    }
}

public struct SettingsDocument: Codable, Sendable, Hashable {
    public static let currentSchemaVersion = 1
    public var schemaVersion: Int
    public var macGlobal: MacGlobalSettings
    public var app: AppSettings

    public init(macGlobal: MacGlobalSettings = .defaults, app: AppSettings = AppSettings()) {
        schemaVersion = Self.currentSchemaVersion; self.macGlobal = macGlobal; self.app = app
    }
}

/// One forward-only, consecutive envelope migration. Throws before publication on any failure.
public struct Migration: Sendable {
    public let fromVersion: Int
    public let toVersion: Int
    private let transform: @Sendable (ProfileDocument) throws -> ProfileDocument

    public init(fromVersion: Int, toVersion: Int, transform: @escaping @Sendable (ProfileDocument) throws -> ProfileDocument) {
        self.fromVersion = fromVersion; self.toVersion = toVersion; self.transform = transform
    }

    public func apply(_ document: ProfileDocument) throws -> ProfileDocument {
        guard document.schemaVersion == fromVersion, toVersion == fromVersion + 1 else { throw ProfileStoreError.invalidMigration }
        let migrated = try transform(document)
        guard migrated.schemaVersion == toVersion, migrated.profile.id == document.profile.id else {
            throw ProfileStoreError.invalidMigration
        }
        return migrated
    }

    /// v2 makes the envelope version independent of the Core profile version; no profile fields change.
    /// v3 adds per-tunnel exclusions (DEC-087): a document without them decodes as having none, and an older build refuses
    /// a v3 envelope instead of silently dropping the list on its next save.
    public static let standard: [Migration] = [
        Migration(fromVersion: 1, toVersion: 2) { document in
            var result = document; result.schemaVersion = 2; return result
        },
        Migration(fromVersion: 2, toVersion: 3) { document in
            var result = document; result.schemaVersion = 3; return result
        },
    ]
}

package enum DocumentCodec {
    package static func encode(_ value: some Encodable) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
}
