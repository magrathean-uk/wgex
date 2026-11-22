// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M05-T05: the daemon side of editing the tunnel that is active, as the official app's `TunnelsManager.modify` does (save,
/// then restart the running tunnel). Requests go through the same XPC composition the app uses.
private struct ActiveProfileEditTests {
    /// Calls that would mean the running tunnel or its blocking policy was touched.
    private static let tunnelCalls: Set<String> = [
        "engine.create", "engine.shutdown", "routes.remove", "dns.remove", "device.remove",
        "pf.disconnecting", "pf.disconnected", "pf.release", "pf.error", "pf.connected",
    ]

    private static func edited(_ profile: TunnelProfile) throws -> TunnelProfile {
        var edited = profile
        edited.interface.dns = try [DNSServer("10.77.0.9")]
        edited.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/1"), IPAddressRange("128.0.0.0/1")]
        return edited
    }

    @Test
    func `startup options saved for the active profile leave the running tunnel untouched`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        let generation = try await fixture.installAndStart()
        let id = fixture.harness.profile.id
        let mark = fixture.harness.trace.calls.count
        // The app's startup save: register the current document, then the dedicated boot-intent request.
        var startup = fixture.harness.profile; startup.macOptions.startBeforeLogin = true
        #expect(try await fixture.call(.installProfileCAS(startup, expectedRevision: 1)) == .profileRevision(1))
        #expect(try await fixture.call(.setStartBeforeLoginIntent(profileID: id, enabled: true)) == .ok)
        #expect(try await fixture.harness.registry.bootIntent()?.profileID == id)
        #expect(await fixture.harness.controller.status.phase == .active(generation))
        #expect(await fixture.harness.controller.status.protection == .protected)
        #expect(await fixture.harness.controller.activeProfileID() == id)
        #expect(fixture.harness.trace.calls.dropFirst(mark).filter(Self.tunnelCalls.contains).isEmpty)

        #expect(try await fixture.call(.setStartBeforeLoginIntent(profileID: id, enabled: false)) == .ok)
        #expect(try await fixture.harness.registry.bootIntent() == nil)
        #expect(await fixture.harness.controller.status.phase == .active(generation))
        #expect(fixture.harness.trace.calls.dropFirst(mark).filter(Self.tunnelCalls.contains).isEmpty)
    }

    @Test
    func `replacing the active profile saves it and restarts it in place without the kill switch dropping`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        let first = try await fixture.installAndStart()
        let id = fixture.harness.profile.id
        let edited = try Self.edited(fixture.harness.profile)
        let saveMark = fixture.harness.trace.calls.count
        #expect(try await fixture.call(.installProfileCAS(edited, expectedRevision: 1)) == .profileRevision(2))
        // Saving alone never touches the running tunnel.
        #expect(await fixture.harness.controller.status.phase == .active(first))
        #expect(fixture.harness.trace.calls.dropFirst(saveMark).filter(Self.tunnelCalls.contains).isEmpty)

        // The app then starts the same profile again: the daemon's restart in place.
        let restartMark = fixture.harness.trace.calls.count
        let second = try await fixture.start()
        #expect(second.rawValue > first.rawValue)
        #expect(await fixture.harness.controller.status.phase == .active(second))
        #expect(await fixture.harness.controller.status.protection == .protected)
        #expect(await fixture.harness.ports.configuredProfiles.last == edited)
        #expect(try await fixture.harness.registry.profile(id, connectionUID: ControllerHarness.uid).profile == edited)

        let restart = Array(fixture.harness.trace.calls.dropFirst(restartMark))
        let policies = restart.filter { $0.hasPrefix("pf.") && $0 != "pf.acquire" }
        // Blocking is loaded before the old tunnel is dismantled and holds until the new one is connected.
        #expect(policies.first == "pf.error")
        #expect(policies.last == "pf.connected")
        #expect(!policies.contains("pf.disconnected") && !policies.contains("pf.disconnecting") && !policies.contains("pf.release"))
        #expect(policies.filter { $0 == "pf.connected" }.count == 1)
        let shutdown = try #require(restart.firstIndex(of: "engine.shutdown"))
        let created = try #require(restart.firstIndex(of: "engine.create"))
        #expect(shutdown < created)
        #expect(try #require(restart.firstIndex(of: "pf.error")) < shutdown)
    }

    @Test
    func `replacing the active profile set to start before login keeps its boot intent`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        let generation = try await fixture.installAndStart()
        let id = fixture.harness.profile.id
        var startup = fixture.harness.profile; startup.macOptions.startBeforeLogin = true
        #expect(try await fixture.call(.installProfileCAS(startup, expectedRevision: 1)) == .profileRevision(1))
        #expect(try await fixture.call(.setStartBeforeLoginIntent(profileID: id, enabled: true)) == .ok)
        // The app's replacement registers the imported configuration with the replaced profile's startup options.
        let replacement = try Self.edited(startup)
        #expect(try await fixture.call(.installProfileCAS(replacement, expectedRevision: 1)) == .profileRevision(2))
        #expect(try await fixture.harness.registry.bootIntent()?.profileID == id)
        // The registry keeps the boot flag in its own override, never in the stored document.
        var canonical = replacement; canonical.macOptions.startBeforeLogin = false
        #expect(try await fixture.harness.registry.profile(id, connectionUID: ControllerHarness.uid).profile == canonical)
        #expect(await fixture.harness.controller.status.phase == .active(generation))
    }

    @Test
    func `a replacement refused half way leaves the old profile active and intact`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        let generation = try await fixture.installAndStart()
        let id = fixture.harness.profile.id
        let original = try await fixture.harness.registry.profile(id, connectionUID: ControllerHarness.uid)
        let mark = fixture.harness.trace.calls.count
        let reply = try await fixture.call(.installProfileCAS(Self.edited(fixture.harness.profile), expectedRevision: 7))
        #expect(reply == .profileRevisionConflict(currentRevision: 1))
        #expect(try await fixture.harness.registry.profile(id, connectionUID: ControllerHarness.uid) == original)
        #expect(await fixture.harness.controller.status.phase == .active(generation))
        #expect(await fixture.harness.controller.status.protection == .protected)
        #expect(fixture.harness.trace.calls.dropFirst(mark).filter(Self.tunnelCalls.contains).isEmpty)
    }

    @Test
    func `a restart that fails half way keeps the kill switch blocking`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        _ = try await fixture.installAndStart()
        #expect(try await fixture
            .call(.installProfileCAS(Self.edited(fixture.harness.profile), expectedRevision: 1)) == .profileRevision(2))
        let mark = fixture.harness.trace.calls.count
        fixture.harness.trace.fail(at: "engine.create")
        await #expect(throws: HostTestError.injected) { _ = try await fixture.start() }
        let status = await fixture.harness.controller.status
        guard case let .failed(_, blockedByPolicy, _) = status.phase else {
            Issue.record("Expected a failed phase, got \(status.phase)"); return
        }
        #expect(blockedByPolicy)
        #expect(status.protection == .blocked)
        let policies = fixture.harness.trace.calls.dropFirst(mark).filter { $0.hasPrefix("pf.") && $0 != "pf.acquire" }
        #expect(!policies.contains("pf.disconnected") && !policies.contains("pf.disconnecting") && !policies.contains("pf.release"))
        #expect(await fixture.harness.ports.policy != .disconnected)
    }

    @Test
    func `an armed profile restarted for an edit is armed again and keeps running`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)))
        #expect(try await rig.arm() == .ok); await rig.idle()
        let first = try #require(await rig.controller.status.phase.generation)
        let edited = try Self.edited(rig.profile)
        // The app's save registers the edit (the dispatcher's `installProfileCAS`), leaving the running tunnel and the arm alone.
        _ = try await rig.harness.registry.installProfile(edited, expectedRevision: 1, connectionUID: OnDemandRig.uid)
        #expect(await rig.controller.status.phase == .active(first))
        #expect(try await rig.armedInRegistry())

        // The app's restart is a start of the same profile, which the daemon treats as a manual connect and disarms (rule 4).
        let reply = try await rig.controller.handle(
            .startIntent(profileID: rig.profile.id, transport: nil, hasSecrets: true), context: rig.context,
            secrets: ControllerHarness.bundle(),
        )
        guard case .started = reply else { Issue.record("restart failed: \(reply)"); return }
        await rig.idle()
        let second = try #require(await rig.controller.status.phase.generation)
        #expect(second.rawValue > first.rawValue)
        #expect(try await !rig.armedInRegistry())

        // The app then arms it again: armed as before, and the restarted tunnel is left as it is.
        let mark = rig.harness.trace.calls.count
        #expect(try await rig.arm() == .ok); await rig.idle()
        #expect(try await rig.armedInRegistry())
        #expect(await rig.onDemand?.armedProfileID == rig.profile.id)
        #expect(await rig.controller.status.phase == .active(second))
        #expect(await rig.controller.status.protection == .protected)
        #expect(await rig.harness.ports.configuredProfiles.last == edited)
        #expect(rig.harness.trace.calls.dropFirst(mark).filter(Self.tunnelCalls.contains).isEmpty)
    }
}
