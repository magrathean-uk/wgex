// SPDX-License-Identifier: MIT

/// Every identifier derived from `WGEX_BUNDLE_ID_BASE` (ADR-016). Nothing here is
/// typed twice: the base and team come from the generated file written by the
/// pre-build step, or from the checked-in development fallback.
public struct BuildIdentifiers: Sendable, Hashable {
    /// Suffix that marks the development (Debug) base.
    public static let developmentSuffix = ".dev"

    /// Identifiers of the running build.
    public static let current = BuildIdentifiers(
        base: BuildIdentifierSource.bundleIDBase,
        team: BuildIdentifierSource.team,
    )

    /// True when ``current`` comes from the generated file rather than the fallback.
    public static var isGenerated: Bool {
        BuildIdentifierSource.isGenerated
    }

    /// Bundle identifier base of the running build.
    public static var base: String {
        current.base
    }

    /// Mach service and launchd label of the running build's daemon.
    public static var daemonService: String {
        current.daemonService
    }

    /// Bundle identifier of the running build's packet tunnel extension.
    public static var tunnelExtension: String {
        current.tunnelExtension
    }

    /// `WGEX_BUNDLE_ID_BASE`, for example `com.magrathean.WGEXApp`.
    public let base: String
    /// Apple Developer team identifier.
    public let team: String

    /// Creates identifiers for an explicit base and team.
    public init(base: String, team: String) {
        self.base = base
        self.team = team
    }

    /// App bundle identifier on every platform.
    public var app: String {
        base
    }

    /// Packet tunnel extension bundle identifier (iOS and tvOS).
    public var tunnelExtension: String {
        base + ".tunnel"
    }

    /// Live Activity extension bundle identifier (iOS).
    public var liveActivityExtension: String {
        base + ".liveactivity"
    }

    /// Daemon launchd label and Mach service name.
    public var daemonService: String {
        base + ".daemon"
    }

    /// Signing identifier of the daemon executable.
    public var daemon: String {
        daemonService
    }

    /// Signing identifier of the `wgex` command-line tool.
    public var cli: String {
        base + ".cli"
    }

    /// App group shared by the app and its extensions.
    public var appGroup: String {
        "group." + base
    }

    /// Keychain access group (`$(AppIdentifierPrefix)<base>`).
    public var keychainAccessGroup: String {
        team + "." + base
    }

    /// Unified logging subsystem.
    public var logSubsystem: String {
        base
    }

    /// File name of the daemon's launchd plist inside `Contents/Library/LaunchDaemons`.
    public var daemonPlistName: String {
        daemonService + ".plist"
    }

    /// True for the development (Debug) base.
    public var isDevelopment: Bool {
        base.hasSuffix(Self.developmentSuffix)
    }

    /// The same identifiers with the development suffix removed.
    public var releaseVariant: BuildIdentifiers {
        guard isDevelopment else { return self }
        return BuildIdentifiers(base: String(base.dropLast(Self.developmentSuffix.count)), team: team)
    }

    /// The same identifiers with the development suffix applied.
    public var developmentVariant: BuildIdentifiers {
        isDevelopment ? self : BuildIdentifiers(base: base + Self.developmentSuffix, team: team)
    }
}
