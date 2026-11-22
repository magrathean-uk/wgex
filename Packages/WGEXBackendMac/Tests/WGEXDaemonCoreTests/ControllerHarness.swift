// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXTesting

package final class ControllerHarness: Sendable {
    package let root: URL
    package let directory: StateDirectory
    package let journal: DaemonJournal
    package let store: DaemonSecretStore
    package let registry: ProfileRegistry
    package let trace = HostTrace()
    package let ports: HostPorts
    package let clock = HostClock()
    package let profile: TunnelProfile
    package let controller: TunnelController
    package static let uid: UInt32 = 501
    package static let underlay = UnderlaySnapshot(v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"])

    package init(
        gate: StepGate = StepGate(),
        secureInstall: any SecureInstallChecking = VerifiedSecureInstall(),
        diagnostics: any DaemonDiagnosticsProviding = UnavailableDaemonDiagnostics(),
        policyFactory: (@Sendable (DaemonJournal) throws -> any DaemonPolicyManaging)? = nil,
        journalTransform: (@Sendable (DaemonJournal) -> any DaemonJournalling)? = nil,
        repositoryTransform: (@Sendable (any ProfileRepository) -> any ProfileRepository)? = nil,
        underlay: UnderlaySnapshot = ControllerHarness.underlay,
        watchdogClock: any DaemonClock? = nil,
        operationLog: (@Sendable (String) -> Void)? = nil,
        portsTransform: (@Sendable (DaemonPorts) -> DaemonPorts)? = nil,
        interfaces: any NetworkInterfaceClassifying = StaticInterfaceClassifier(),
        secretsTransform: (@Sendable (any TunnelSecretStoring) -> any TunnelSecretStoring)? = nil,
    ) throws {
        root = try StateDirectory.temporaryRoot().appendingPathComponent("wgex-core-" + UUID().uuidString)
        directory = try StateDirectory(root: root)
        journal = try DaemonJournal(directory: directory)
        store = try DaemonSecretStore(directory: directory, keyProvider: InMemoryDaemonKeyProvider(key: Self.wrappingKey()))
        let repository = try DirectoryProfileRepository(directory: directory)
        registry = ProfileRegistry(repository: repositoryTransform?(repository) ?? repository, secrets: store, bundles: store)
        ports = HostPorts(trace: trace)
        profile = try Self.makeProfile()
        let seams = try DaemonPorts(
            engineFactory: ports,
            routes: ports,
            dns: ports,
            policy: policyFactory?(journal) ?? ports,
            resolver: ports,
            device: ports,
            verifier: ports,
            reality: ports,
        )
        let spy = ControllerSecretSpy(base: store, trace: trace)
        controller = TunnelController(
            registry: registry, secureInstall: secureInstall,
            journal: journalTransform?(journal) ?? journal,
            secrets: secretsTransform?(spy) ?? spy,
            ports: portsTransform?(seams) ?? seams,
            underlay: underlay,
            clock: clock,
            steps: gate, diagnostics: diagnostics, operationClock: watchdogClock ?? clock,
            operationLog: operationLog, interfaces: interfaces,
        )
    }

    deinit { try? FileManager.default.removeItem(at: root) }
    package func install() async throws {
        try await registry.installProfile(profile, expectedRevision: nil, connectionUID: Self.uid)
    }

    package func start() async throws -> Generation {
        try await controller.start(profileID: profile.id, connectionUID: Self.uid, secrets: Self.bundle())
    }

    package func replacementController(
        steps: any DaemonStepObserving = UninterruptedDaemonSteps(),
        secureInstall: any SecureInstallChecking = VerifiedSecureInstall(),
        operationLog: (@Sendable (String) -> Void)? = nil,
        operationClock: any DaemonClock? = nil,
        portsTransform: (@Sendable (DaemonPorts) -> DaemonPorts)? = nil,
        interfaces: any NetworkInterfaceClassifying = StaticInterfaceClassifier(),
        repositoryTransform: (@Sendable (any ProfileRepository) -> any ProfileRepository)? = nil,
    ) throws -> TunnelController {
        let reopened = try StateDirectory(root: root)
        let freshStore = try DaemonSecretStore(directory: reopened, keyProvider: InMemoryDaemonKeyProvider(key: Self.wrappingKey()))
        let repository = try DirectoryProfileRepository(directory: reopened)
        let freshRegistry = ProfileRegistry(
            repository: repositoryTransform?(repository) ?? repository,
            secrets: freshStore,
            bundles: freshStore,
        )
        let seams = DaemonPorts(
            engineFactory: ports,
            routes: ports,
            dns: ports,
            policy: ports,
            resolver: ports,
            device: ports,
            verifier: ports,
            reality: ports,
        )
        return try TunnelController(
            registry: freshRegistry, secureInstall: secureInstall,
            journal: DaemonJournal(directory: reopened),
            secrets: freshStore,
            ports: portsTransform?(seams) ?? seams,
            underlay: Self.underlay,
            clock: clock, steps: steps, operationClock: operationClock ?? clock, operationLog: operationLog, interfaces: interfaces,
        )
    }

    private static func wrappingKey() throws -> SecretBytes {
        try fixtureKey("psk1.key")
    }

    package static func testKey() throws -> SecretBytes {
        try fixtureKey("client1.key")
    }

    private static func fixtureKey(_ name: String) throws -> SecretBytes {
        var data = try FixtureLoader.repository().data("keys/" + name)
        let input = try SecretBytes(wiping: &data)
        let range: Range<Int>? = input.withUnsafeBytes { raw in
            var start = 0
            for end in raw.indices where raw[end] == 10 {
                if start < end, raw[start] != 35 {
                    return start ..< (raw[end - 1] == 13 ? end - 1 : end)
                }
                start = end + 1
            }
            return nil
        }
        guard let range else { throw HostTestError.injected }
        let text = try SecretBytes(copying: input, range: range)
        let key = try PrivateKey(parsing: text, encoding: .base64)
        var bytes = try SecretBytes(zeroedCount: 32)
        try key.encode(into: &bytes)
        return bytes
    }

    package static func bundle() throws -> SecretBundle {
        try bundle(keyFile: "client1.key")
    }

    /// A bundle holding the fixture private key `keyFile` (`client1.key` is the profile's own key).
    package static func bundle(keyFile: String) throws -> SecretBundle {
        let writer = try SecretsWireWriter(privateKey: fixtureKey(keyFile))
        return try SecretsWireLayout.decode(writer.finish())
    }

    /// The public key of the fixture private key `keyFile`.
    package static func publicKey(keyFile: String) throws -> PublicKey {
        try PrivateKey(bytes: fixtureKey(keyFile)).publicKey()
    }

    package static func makeProfile() throws -> TunnelProfile {
        let key = try PrivateKey(bytes: testKey())
        let peerKey = try PrivateKey(bytes: fixtureKey("client2.key"))
        var profile = TunnelProfile(name: "Host fixture")
        profile.interface = try InterfaceConfiguration(
            addresses: [IPAddressRange("10.77.0.2/32")],
            dns: [DNSServer("10.77.0.1")],
            publicKey: key.publicKey(),
        )
        profile.peers = try [PeerConfiguration(
            publicKey: peerKey.publicKey(),
            allowedIPs: [IPAddressRange("0.0.0.0/0")],
            endpoint: Endpoint("peer.example.test:51820"),
        )]
        profile.protection.ipv6Policy = .blockOutside
        return profile
    }
}
