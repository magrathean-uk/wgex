// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

public extension TunnelController {
    func openCaptiveWindow(seconds: Int, connectionUID: UInt32) async throws {
        guard (1 ... 3600).contains(seconds), (1 ... 3600).contains(settings.captiveWindowSeconds),
              seconds <= settings.captiveWindowSeconds else { throw DaemonFailure.controllerInvalidConfiguration }
        try await requireSecureInstall()
        await drainLifecycle()
        guard !needsRecovery, let intended, intended.ownerUID == connectionUID || connectionUID == 0,
              (1 ... settings.captiveWindowSeconds).contains(seconds)
        else { throw DaemonFailure(code: .captiveUnavailable) }
        if let current = journal.snapshot().captiveWindow {
            _ = try CaptiveWindowModel.extend(
                current, seconds: seconds, maximum: settings.captiveWindowSeconds, continuous: clock.now, wall: clock.wallNow,
            )
        }
        try await maintenance { controller, epoch in try await controller.performOpenCaptive(seconds: seconds, generation: epoch) }
    }

    private func performOpenCaptive(seconds: Int, generation: Generation) async throws {
        if let current = journal.snapshot().captiveWindow {
            let next = try CaptiveWindowModel.extend(
                current, seconds: seconds, maximum: settings.captiveWindowSeconds, continuous: clock.now, wall: clock.wallNow,
            )
            try journal.mutate(generation: generation) { $0.captiveWindow = next }
            try await applyCaptivePolicy(.captiveWindow(expires: next.expiresAtWall), generation: generation)
            transition(.captiveWindow(generation, expires: next.expiresAtWall), protection: .captiveWindow(expires: next.expiresAtWall))
            scheduleCaptiveClose(after: max(.zero, next.continuousDeadline - clock.now))
            return
        }
        try await checkpoint(.openCaptive, generation: generation)
        try await applyCaptivePolicy(.error, generation: generation)
        do { try await ports.dns.remove(generation: generation) }
        catch { throw DaemonFailure(code: .captiveDNSFailed) }
        try check(generation)
        do { try await ports.routes.removeRoutes(of: generation) }
        catch { throw DaemonFailure(code: .captiveRoutesFailed) }
        try check(generation)
        let window = try CaptiveWindowModel.open(
            seconds: seconds, maximum: settings.captiveWindowSeconds, continuous: clock.now, wall: clock.wallNow,
        )
        let expires = window.expiresAtWall
        try journal.mutate(generation: generation) { $0.captiveWindow = window }
        try await applyCaptivePolicy(.captiveWindow(expires: expires), generation: generation)
        try entry(.openCaptive, .didApply, generation: generation)
        transition(.captiveWindow(generation, expires: expires), protection: .captiveWindow(expires: expires))
        rotation.retryTask?.cancel(); rotation.retryTask = nil
        maintenanceState.retryAt = nil
        scheduleCaptiveClose(after: .seconds(seconds))
    }

    private func applyCaptivePolicy(_ policy: PacketFilterPolicy, generation: Generation) async throws {
        do { try await applyPolicy(policy, generation: generation) }
        catch { throw DaemonFailure(code: .captivePolicyFailed) }
    }

    private func scheduleCaptiveClose(after duration: Duration) {
        captiveTask?.cancel()
        captiveTask = Task { [weak self, clock] in
            do { try await clock.sleep(for: duration); try Task.checkCancellation(); try await self?.closeCaptiveWindow() }
            catch { /* Cancellation is expected on replacement or manual close. The journal retains a failed close. */ }
        }
    }

    func closeCaptiveWindow() async throws {
        await drainLifecycle()
        guard journal.snapshot().captiveWindow != nil else { return }
        let epoch = generation
        let restart = engines[epoch] == nil ? intended : nil
        try await maintenance { controller, epoch in try await controller.performCloseCaptive(generation: epoch) }
        let timer = captiveTask; captiveTask = nil
        defer { timer?.cancel() }
        if let restart {
            _ = try await self.restart(restart, expectedGeneration: epoch)
        }
    }

    private func performCloseCaptive(generation: Generation) async throws {
        try withdrawCaptiveException()
        try await checkpoint(.closeCaptive, generation: generation)
        try await applyPolicy(.error, generation: generation)
        try await requireSecureInstall()
        let resources = resource(generation)
        guard let engine = engines[generation], let identity = resources.identity else {
            guard intended != nil else { throw DaemonFailure(code: .captiveUnavailable) }
            try journal.mutate(generation: generation) { $0.captiveWindow = nil }
            try entry(.closeCaptive, .didApply, generation: generation)
            transition(.reasserting(generation, reason: .pathChanged), protection: .blocked)
            return
        }
        try await ports.routes.install(resources.routes, generation: generation)
        try check(generation)
        if let dns = resources.dns {
            try await ports.dns.apply(dns, generation: generation)
        }
        try check(generation)
        try journal.mutate(generation: generation) { $0.captiveWindow = nil }
        try await applyPolicy(.connected(interfaceName: identity.name, endpoints: endpointAddresses), generation: generation)
        try await verifyOffActor(ProtectionExpectation(resources: resources, policy: journal.snapshot().pfPolicy, engine: engine))
        try await verifyPolicy()
        try check(generation); try entry(.closeCaptive, .didApply, generation: generation)
        transition(.active(generation), protection: .protected)
    }
}
