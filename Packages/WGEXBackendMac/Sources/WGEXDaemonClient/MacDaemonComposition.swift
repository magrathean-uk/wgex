// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// Pure app composition, injectable without constructing XPC, Keychain or a service controller.
/// The guard also covers settings operations, not just the initial handshake.
public struct MacDaemonComposition: Sendable {
    public let client: DaemonClient
    private let systemOperationsPermitted: Bool
    private let authorizeSecureInstall: @Sendable () async throws -> any SecureInstallGrant

    public init(
        transport: any XPCTransport, clientVersion: String, clientBuild: Int,
        secretStore: any SecretStore, systemOperationsPermitted: Bool,
        authorizeSecureInstall: @escaping @Sendable () async throws
            -> any SecureInstallGrant = { throw DaemonError.notAuthorised(.adminRightRequired) },
    ) {
        // Compatibility is independent of the currently shipped application build.
        client = DaemonClient(
            transport: transport, clientVersion: clientVersion, clientBuild: clientBuild,
            minimumDaemonBuild: ProtocolCompatibility.minimumDaemonBuild, secretStore: secretStore, surfaceVisible: false,
        )
        self.systemOperationsPermitted = systemOperationsPermitted
        self.authorizeSecureInstall = authorizeSecureInstall
    }

    public func start(profiles: [TunnelProfile]) async throws {
        try checkGuard()
        for profile in profiles {
            // Unsupported legacy references must not suppress daemon reachability.
            try? await registerSecretReferences(profile)
        }
        try await refreshDaemon()
    }

    /// Profiles written by the import transaction retain the SecretID UUID in daemonStore refs.
    /// Opaque legacy Keychain persistent refs cannot be reconstructed as SecretStore accounts.
    public func registerSecretReferences(_ profile: TunnelProfile) async throws {
        func account(_ reference: SecretRef, kind: SecretID.Kind) throws -> SecretID {
            guard case let .daemonStore(id) = reference else { throw TunnelError.secretsUnavailable }
            return SecretID(profileID: profile.id, kind: kind, id: id)
        }
        let references = try AppSecretReferences(
            privateKey: account(profile.secrets.privateKey, kind: .privateKey),
            presharedKeys: profile.secrets.presharedKeys.mapValues { try account($0, kind: .presharedKey) },
            carrierCredentials: profile.secrets.carrierCredentials.mapValues { try account($0, kind: .carrierCredential) },
        )
        await client.setSecretReferences(references, for: profile.id)
    }

    @discardableResult
    public func refreshDaemon() async throws -> Bool {
        try checkGuard()
        _ = try await client.connect()
        return true
    }

    /// Queries install evidence without requesting an administrative grant.
    public func secureInstallStatus() async throws -> SecureInstallState {
        try checkGuard()
        return try await Self.installState(client.secureInstallStatus())
    }

    public func secureInstall() async throws -> SecureInstallState {
        try checkGuard()
        let initial = try await client.secureInstallStatus()
        // Ownership, ACL, mode and wrapping-key faults are repairable; never raise an admin prompt for a
        // bundle outside /Applications or one whose identity the daemon rejected.
        guard case let .needsAttention(reason) = initial.state,
              [.notRootOwned, .bundleWritable, .aclWritable, .wrappingKeyUnavailable, .wrappingKeyRepairFailed].contains(reason)
        else {
            return Self.installState(initial)
        }
        // The grant stays alive until the daemon has verified the external form and replied.
        let grant = try await authorizeSecureInstall()
        let repaired = try await client.performSecureInstall(authorization: grant.externalForm)
        withExtendedLifetime(grant) {}
        return Self.installState(repaired)
    }

    public static func installState(_ report: SecureInstallReport) -> SecureInstallState {
        switch report.state {
        case .verified: .verified
        case .inProgress: .checking
        case .needsAttention(.notInApplications): .needsAttention(.notInApplications)
        case .needsAttention(.bundleWritable), .needsAttention(.notRootOwned), .needsAttention(.aclWritable),
             .needsAttention(.wrappingKeyUnavailable), .needsAttention(.wrappingKeyRepairFailed): .needsAttention(.bundleWritable)
        case .needsAttention: .needsAttention(.serviceNotVerified)
        }
    }

    /// Explicit user action: obtain the admin right and hold it through daemon preparation.
    public func finishUpdate(
        service: any ServiceControlling,
        changed: @escaping @Sendable (UpdateHandoffState) async -> Void,
    ) async throws {
        try checkGuard()
        let grant = try await authorizeSecureInstall()
        try await DaemonUpdateHandoff.run(
            client: client,
            service: service,
            currentBuild: client.clientBuild,
            grant: grant,
            changed: changed,
        )
        let hello = try await client.connect()
        guard await hello.daemonBuild == client.clientBuild else { throw DaemonError.disconnected }
    }

    public func saveStartup(_ profile: TunnelProfile, options: MacProfileOptions) async throws {
        try checkGuard()
        try await registerSecretReferences(profile)
        // Register the current document; boot intent changes only after the dedicated request succeeds.
        try await client.install(profile)
        try await client.setStartBeforeLogin(profile.id, enabled: options.startBeforeLogin)
    }

    public func openCaptiveWindow(seconds: Int) async throws {
        try checkGuard()
        try await expectOK(.openCaptiveWindow(seconds: seconds))
    }

    public func closeCaptiveWindow() async throws {
        try checkGuard()
        try await expectOK(.closeCaptiveWindow)
    }

    private func expectOK(_ request: Request) async throws {
        guard case .ok = try await client.request(request) else { throw DaemonError.malformedMessage }
    }

    private func checkGuard() throws {
        guard systemOperationsPermitted else { throw ServiceError.hostGuard }
    }
}
