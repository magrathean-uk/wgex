// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// ADR-030 daemon behaviour on the real controller with host fakes: arming, section 6 rules, sections 4 and 7, report
/// freshness, the section 3 SSID transitions and restart persistence.
internal final class Shared<Value: Sendable>: Sendable {
    private let state: Mutex<Value>
    internal init(_ value: Value) {
        state = Mutex(value)
    }

    internal func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        state.withLock { body(&$0) }
    }
}

internal final class OnDemandRig: Sendable {
    internal static let uid = ControllerHarness.uid
    internal static let wifi = UnderlaySnapshot(
        v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["en0"], interfaceV4Name: "en0",
    )
    internal static let ethernet = UnderlaySnapshot(
        v4: 7, v6: 8, resolvers: ["192.0.2.53"], interfaceNames: ["en7"], interfaceV4Name: "en7",
    )

    internal let harness: ControllerHarness
    internal let profile: TunnelProfile
    internal let reporters = Shared(0)
    internal let requested = Shared<[String]>([])
    /// The reporter standing the dispatcher would attach to this rig's reports.
    internal let membership = WiFiReporterMembership()
    private let observer: Task<Void, Never>

    internal var controller: TunnelController {
        harness.controller
    }

    internal init(
        _ policy: OnDemandPolicy, underlay: UnderlaySnapshot = OnDemandRig.ethernet, console: Bool = true,
        repository: (@Sendable (any ProfileRepository) -> any ProfileRepository)? = nil, steps: StepGate = StepGate(),
        secrets: (@Sendable (any TunnelSecretStoring) -> any TunnelSecretStoring)? = nil,
        secureInstall: any SecureInstallChecking = VerifiedSecureInstall(),
    ) async throws {
        harness = try ControllerHarness(
            gate: steps, secureInstall: secureInstall, repositoryTransform: repository, underlay: underlay,
            interfaces: StaticInterfaceClassifier(wifi: ["en0"]),
            secretsTransform: secrets,
        )
        var profile = harness.profile
        profile.onDemand = policy
        self.profile = profile
        try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: Self.uid)
        let events = harness.controller.wireEvents.observe()
        observer = Task { [requested] in
            for await item in events {
                if case let .wifiNetworkRequested(name) = item.event {
                    requested.withLock { $0.append(name) }
                }
            }
        }
        await harness.controller.setOnDemandReporters { [reporters] in reporters.withLock { $0 } }
        if console {
            try await harness.controller.consoleUserChanged(Self.uid)
        }
    }

    deinit { observer.cancel() }

    internal var context: DaemonRequestContext {
        DaemonRequestContext(
            peer: VerifiedPeerIdentity(uid: Self.uid, pid: 1, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [profile.id], clientBuild: 1, wifiReporter: membership,
        )
    }

    @discardableResult
    internal func arm(_ id: UUID? = nil) async throws -> Reply {
        try await controller.handle(
            .armOnDemand(profileID: id ?? profile.id, hasSecrets: true),
            context: context,
            secrets: ControllerHarness.bundle(),
        )
    }

    @discardableResult
    internal func send(_ request: Request) async -> Reply {
        await controller.handle(request, context: context, secrets: nil)
    }

    @discardableResult
    internal func report(_ reading: WiFiReading, interface: String = "en0", at time: TimeInterval? = nil) async -> Reply {
        await send(.reportWiFiNetwork(WiFiObservation(
            interfaceName: interface, reading: reading, observedAtContinuous: time ?? XPCClock.continuousSeconds,
        )))
    }

    internal func idle() async {
        await controller.awaitOnDemandIdle()
    }

    /// Waits until a settle timer of `seconds` is registered on the host clock; bounded and cancellable.
    internal func settling(_ seconds: Int64 = 3) async throws {
        try await waitForCondition { [harness] in harness.clock.pendingSleeps.contains(.seconds(seconds)) }
    }

    internal func underlay(_ snapshot: UnderlaySnapshot) async throws {
        try await controller.networkChanged(trigger: .configuration, underlay: UnderlayEvent(snapshot: snapshot, satisfied: true))
        await idle()
    }

    internal var onDemand: OnDemandStatus? {
        get async { await controller.status.onDemand }
    }

    internal var intent: TunnelIntent? {
        harness.journal.snapshot().intent
    }

    /// The durable on-demand record as a fresh daemon would read it.
    internal func record() throws -> OnDemandRecord? {
        try DirectoryProfileRepository(directory: harness.directory).loadOnDemandRecord()
    }

    /// The public key of the stored bundle's private key.
    internal func storedKey(_ id: UUID? = nil) async throws -> PublicKey {
        let bundle = try await SecretsWireLayout.decode(harness.store.loadBundle(profileID: id ?? profile.id))
        return try PrivateKey(bytes: bundle.privateKey()).publicKey()
    }

    internal func armedInRegistry(_ id: UUID? = nil) async throws -> Bool {
        try await harness.registry.armedProfile()?.registration.profile.id == (id ?? profile.id)
    }

    internal func secretsStored(_ id: UUID? = nil) async -> Bool {
        await (try? harness.store.loadBundle(profileID: id ?? profile.id)) != nil
    }

    internal func installOther(_ policy: OnDemandPolicy = .off) async throws -> TunnelProfile {
        let other = TunnelProfile(
            name: "Other", interface: profile.interface, peers: profile.peers, secrets: profile.secrets, transport: profile.transport,
            protection: profile.protection, onDemand: policy, macOptions: profile.macOptions,
        )
        try await harness.registry.installProfile(other, expectedRevision: nil, connectionUID: Self.uid)
        return other
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct OnDemandCoordinatorTests {
    // MARK: Arming and decisions

    @Test
    func `arming connects with origin on-demand and publishes armed and activated status`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)))
        #expect(try await rig.arm() == .ok)
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid, origin: .onDemand))
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
        let status = try #require(await rig.onDemand)
        #expect(status.armedProfileID == rig.profile.id && status.activated && status.network == .ethernet)
        #expect(status.decision == .connect && status.ssid == .notRequired && status.evaluatedAtContinuous != nil)
        #expect(try await rig.armedInRegistry())
        #expect(Envelope.currentProtocolVersion == 8)
    }

    @Test
    func `a disconnect decision stops with the on-demand reason, clears intent and keeps secrets`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        try await rig.underlay(OnDemandRig.wifi)
        #expect(rig.intent == nil)
        #expect(await rig.controller.status.phase == .idle)
        #expect(await rig.controller.status.protection == .unprotected)
        #expect(await rig.harness.ports.policy == .disconnected)
        #expect(rig.harness.journal.snapshot().loginSuspended != true)
        #expect(await rig.secretsStored())
        #expect(await rig.onDemand?.decision == .disconnect)
        #expect(await rig.onDemand?.activated == false)
        #expect(try await rig.armedInRegistry())
        // Back on Ethernet the armed profile connects again from the retained secrets.
        try await rig.underlay(OnDemandRig.ethernet)
        #expect(rig.intent?.startedOnDemand == true)
    }

    @Test
    func `lockdown wins over a disconnect decision`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.controller.setGlobalSettings(MacGlobalSettings(
            lockdown: true,
            allowLAN: false,
            captiveWindowSeconds: 300,
            notifications: true,
        ))
        try await rig.arm(); await rig.idle()
        try await rig.underlay(OnDemandRig.wifi)
        #expect(rig.intent == nil)
        #expect(await rig.harness.ports.policy == .lockdown)
        #expect(await rig.controller.status.protection == .blocked)
        #expect(await rig.controller.currentSettings().lockdown)
    }

    @Test
    func `evaluation pauses while the owner is not the console user and resumes on return`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)), console: false)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.onDemand?.decision == .paused(.ownerNotConsoleUser))
        try await rig.controller.consoleUserChanged(OnDemandRig.uid); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
    }

    @Test
    func `arming refuses a policy that compiles to no macOS rules`() async throws {
        let rig = try await OnDemandRig(.off)
        #expect(try await rig.arm() == .error(.onDemandNotConfigured))
        #expect(try await !rig.armedInRegistry())
        let cellular = try await rig.installOther(.cellularOnly)
        #expect(try await rig.arm(cellular.id) == .error(.onDemandNotConfigured))
    }

    // MARK: Section 6 manual rules

    @Test
    func `rule 2 disarm stops the intended profile`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(await rig.send(.disarmOnDemand(profileID: rig.profile.id)) == .ok)
        #expect(rig.intent == nil)
        #expect(try await !rig.armedInRegistry())
        #expect(await rig.controller.onDemandArmedProfileID == nil)
        #expect(await !rig.secretsStored())
    }

    @Test
    func `disarming a profile that is not intended drops its armed secret retention`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.secretsStored())
        #expect(await rig.send(.disarmOnDemand(profileID: rig.profile.id)) == .ok)
        #expect(await !rig.secretsStored())
    }

    @Test
    func `rule 3 a manual disconnect disarms first, then stops explicitly`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        #expect(await rig.send(.stop(profileID: rig.profile.id, reason: .userRequested)) == .ok)
        await rig.idle()
        #expect(rig.intent == nil)
        #expect(try await !rig.armedInRegistry())
        #expect(await !rig.secretsStored())
    }

    @Test
    func `rule 4 a manual connect disarms and connects with manual origin`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.onDemand?.decision == .disconnect)
        let reply = try await rig.controller.handle(
            .startIntent(profileID: rig.profile.id, transport: nil, hasSecrets: true), context: rig.context,
            secrets: ControllerHarness.bundle(),
        )
        guard case .started = reply else { Issue.record("start failed: \(reply)"); return }
        await rig.idle()
        #expect(rig.intent == TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid))
        #expect(try await !rig.armedInRegistry())
        #expect(await rig.onDemand?.armedProfileID == nil)
    }

    @Test
    func `rule 5 connecting another profile disarms the armed one`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther()
        try await rig.arm(); await rig.idle()
        let reply = try await rig.controller.handle(
            .startIntent(profileID: other.id, transport: nil, hasSecrets: true), context: rig.context, secrets: ControllerHarness.bundle(),
        )
        #expect(reply == .error(.anotherTunnelActive) || reply == .error(.tunnel(.anotherTunnelActive)))
        #expect(try await !rig.armedInRegistry())
        #expect(rig.intent?.profileID == rig.profile.id)
    }

    @Test
    func `rule 6 arming while another profile is intended holds`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)))
        let other = try await rig.installOther()
        _ = try await rig.controller.start(profileID: other.id, connectionUID: OnDemandRig.uid, secrets: ControllerHarness.bundle())
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.profileID == other.id)
        #expect(await rig.onDemand?.decision == .hold(.anotherTunnelActive))
        // The end of the other intent is a trigger: the armed profile then connects.
        try await rig.controller.stop(profileID: other.id, connectionUID: OnDemandRig.uid)
        await rig.idle()
        #expect(rig.intent?.profileID == rig.profile.id)
        #expect(rig.intent?.startedOnDemand == true)
    }

    @Test
    func `rule 7 an install setting the policy to off disarms and leaves the tunnel`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        var off = rig.profile; off.onDemand = .off
        let reply = await rig.controller.installProfileCAS(off, expectedRevision: 1, context: rig.context)
        #expect(reply == .profileRevision(2))
        await rig.idle()
        #expect(try await !rig.armedInRegistry())
        #expect(await rig.controller.onDemandArmedProfileID == nil)
        #expect(rig.intent?.profileID == rig.profile.id)
        #expect(await rig.secretsStored())
    }

    @Test
    func `an install never arms and keeps the flag across policy edits`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        let other = try await rig.installOther(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        var edited = rig.profile; edited.onDemand = .interfaces(.wifiOrEthernet(.anySSID))
        #expect(await rig.controller.installProfileCAS(edited, expectedRevision: 1, context: rig.context) == .profileRevision(2))
        await rig.idle()
        #expect(try await rig.armedInRegistry())
        #expect(try await !rig.armedInRegistry(other.id))
        #expect(rig.intent?.startedOnDemand == true)
    }

    @Test
    func `rule 8 removing the armed profile disarms it`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        #expect(await rig.send(.removeProfile(rig.profile.id, purgeSecrets: false)) == .ok)
        #expect(await rig.controller.onDemandArmedProfileID == nil)
        #expect(try await rig.harness.registry.armedProfile() == nil)
        #expect(await !rig.secretsStored())
    }

    @Test
    func `arming one profile disarms the other and stops it when intended`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther(.interfaces(.wifiOnly(.anySSID)))
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.profileID == rig.profile.id)
        try await rig.arm(other.id); await rig.idle()
        #expect(try await rig.armedInRegistry(other.id))
        #expect(rig.intent == nil) // The other profile's wifiOnly rules disconnect on Ethernet.
        #expect(await !rig.secretsStored(rig.profile.id))
        #expect(await rig.secretsStored(other.id))
    }

    @Test
    func `arming is refused while a cutover is armed`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let other = try await rig.installOther()
        _ = try await rig.controller.startCutover(
            profileID: other.id, connectionUID: OnDemandRig.uid, confirmWithin: 300, secrets: ControllerHarness.bundle(),
        )
        #expect(try await rig.arm() == .error(.busy))
        #expect(try await !rig.armedInRegistry())
    }
}

/// ADR-030 sections 3 and 4 SSID transitions, and restart persistence.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandSSIDAndRestartTests {
    // MARK: Section 3 and 4 SSID transitions

    @Test
    func `arming an include list on an unchanged Wi-Fi network asks for a reading and a listed SSID connects`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm()
        try await rig.settling()
        #expect(rig.requested.withLock { $0 } == ["en0"])
        #expect(await rig.onDemand?.ssid == .settling)
        await rig.report(.ssid("Home"))
        await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.onDemand?.ssid == .known)
        #expect(await rig.onDemand?.decision == .connect)
    }

    @Test
    func `no report settles after three seconds to hold with the SSID timed out`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm()
        try await rig.settling()
        rig.harness.clock.advance(.seconds(3))
        await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.onDemand?.decision == .hold(.ssidUnavailable))
        #expect(await rig.onDemand?.ssid == .unavailable(.timedOut))
    }

    @Test
    func `stale, foreign-interface and pre-invalidation reports are ignored`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm()
        try await rig.settling()
        #expect(await rig.report(.ssid("Home"), at: 0) == .ok)
        #expect(await rig.report(.ssid("Home"), interface: "en1") == .ok)
        #expect(await rig.onDemand?.ssid == .settling)
        #expect(rig.intent == nil)
        await rig.report(.ssid("Home"))
        await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
    }

    @Test
    func `an install that changes the armed list invalidates and asks again`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        var edited = rig.profile; edited.onDemand = .interfaces(.wifiOnly(.onlySSIDs(["Office"])))
        #expect(await rig.controller.installProfileCAS(edited, expectedRevision: 1, context: rig.context) == .profileRevision(2))
        try await rig.settling()
        #expect(rig.requested.withLock { $0 } == ["en0", "en0"])
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent == nil) // "Home" is no longer listed: disconnect.
    }

    @Test
    func `losing the last reporter under an exclude list starts the tunnel at once`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.onDemand?.decision == .disconnect)
        rig.reporters.withLock { $0 = 0 }
        await rig.controller.wifiReporterLost(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.onDemand?.ssid == .unavailable(.noReporter))
    }

    @Test
    func `losing one of two reporters asks the remaining one and settles`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 2 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.ssid("Home")); await rig.idle()
        rig.reporters.withLock { $0 = 1 }
        await rig.controller.wifiReporterLost()
        try await rig.settling()
        #expect(rig.requested.withLock { $0 }.count == 2)
        #expect(await rig.onDemand?.ssid == .settling)
        #expect(rig.intent == nil)
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent == nil)
    }

    @Test
    func `a Location change each way starts and then stops under an exclude list`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.notAuthorised); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.onDemand?.ssid == .unavailable(.notAuthorised))
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent == nil)
        #expect(await rig.secretsStored())
    }

    @Test
    func `without a reporter an include list holds and SSID-free policies need no app`() async throws {
        let include = try await OnDemandRig(.interfaces(.wifiOrEthernet(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        try await include.arm(); await include.idle()
        #expect(include.intent == nil)
        #expect(await include.onDemand?.decision == .hold(.ssidUnavailable))
        #expect(await include.onDemand?.ssid == .unavailable(.noReporter))
        #expect(include.requested.withLock { $0 }.isEmpty)
        let free = try await OnDemandRig(.interfaces(.wifiOnly(.anySSID)), underlay: OnDemandRig.wifi)
        try await free.arm(); await free.idle()
        #expect(free.intent?.startedOnDemand == true)
        #expect(await free.onDemand?.ssid == .notRequired)
    }

    // MARK: Restart persistence

    @Test
    func `armed state and on-demand origin survive a daemon restart`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)), underlay: ControllerHarness.underlay)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        await rig.controller.cancelBackgroundWork()
        let replacement = try rig.harness.replacementController()
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        #expect(await replacement.onDemandArmedProfileID == rig.profile.id)
        #expect(try DaemonJournal(directory: rig.harness.directory).snapshot().intent?.startedOnDemand == true)
        let status = try #require(await replacement.status.onDemand)
        #expect(status.activated && status.armedProfileID == rig.profile.id)
        #expect(status.decision == .paused(.ownerNotConsoleUser))
    }

    @Test
    func `an armed start-before-login profile gets no boot reservation and the coordinator starts it`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)), underlay: ControllerHarness.underlay, console: false)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent == nil)
        try await rig.harness.registry.setStartBeforeLogin(rig.profile.id, enabled: true, connectionUID: OnDemandRig.uid)
        await rig.controller.cancelBackgroundWork()
        let replacement = try rig.harness.replacementController()
        try await replacement.reconcileAtStartup()
        await replacement.awaitOnDemandIdle()
        let intent = try DaemonJournal(directory: rig.harness.directory).snapshot().intent
        #expect(intent?.profileID == rig.profile.id)
        #expect(intent?.startedOnDemand == true)
        #expect(await replacement.status.onDemand?.decision == .connect)
    }
}
