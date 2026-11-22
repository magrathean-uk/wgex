// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXDaemonProtocol

public enum PFVerificationStatus: String, Sendable {
    case unknown, unprotected, rulesVerified, blocked, protected, captiveWindow
}

/// The seam reports the last successfully loaded policy; verificationStatus carries
/// uncertainty because PacketFilterPolicy has no unknown case. Routes/DNS/engine
/// verification is still the controller's responsibility before claiming protection.
public actor PolicyEnforcer: DaemonPolicyManaging {
    private let canaryProbe: (@Sendable () async throws -> Void)?
    private var profile: TunnelProfile?
    private let runner: PFCtl
    private let lifecycle: PFTokenLifecycle
    private var context: PFContext
    private var modifiers: PFModifiers
    private var loadedPolicy: PacketFilterPolicy = .disconnected
    private var token: String?
    private var needsReferenceCheck: Bool
    private let slot = SerialOperationSlot()
    private var loadedText: String?
    private var appliedText: String?
    private var loadedCanonical: [String] = []
    private var canaryBaseline: UInt64 = 0
    private var referenceTick = 0
    private var stockCheckedForApply = false
    private var blockingInterfaces: Set<PFInterface> = []
    private var underlayIdentity: PFUnderlayIdentity?
    private var blockingUnderlayIdentity: PFUnderlayIdentity?
    /// A previous process's reference or attempt was journalled; cleared once a recovery load is verified (M1-20).
    private var recovering: Bool
    public private(set) var verificationStatus: PFVerificationStatus = .unknown
    public private(set) var siblingAnchors = ""

    public init(
        runner: PFCtl,
        journal: any PFTokenJournalling,
        context: PFContext,
        modifiers: PFModifiers = PFModifiers(),
        canaryProbe: (@Sendable () async throws -> Void)? = nil,
        bootSession: UUID? = nil,
        onExternalRelease: @escaping @Sendable () -> Void = {},
    ) throws {
        self.canaryProbe = canaryProbe
        self.runner = runner; self.context = context; self.modifiers = modifiers
        lifecycle = try PFTokenLifecycle(
            runner: runner,
            journal: journal,
            bootSession: bootSession,
            onExternalRelease: onExternalRelease,
        )
        let state = try journal.readState()
        token = state.token
        needsReferenceCheck = state.token != nil || state.attempt != nil; recovering = needsReferenceCheck
    }

    public func configure(context: PFContext, modifiers: PFModifiers) async throws {
        try await slot.acquire(); defer { slot.release() }
        try configureContext(context, modifiers: modifiers)
    }

    private func configureContext(_ context: PFContext, modifiers: PFModifiers) throws {
        self.context = context; self.modifiers = modifiers
        if let loadedText, let (phase, effectiveModifiers, effectiveContext) = try? model(for: loadedPolicy),
           (try? PacketFilterRenderer.render(phase: phase, modifiers: effectiveModifiers, context: effectiveContext)) ==
           loadedText
        {
            return
        }
        loadedText = nil
        verificationStatus = .unknown
    }

    public func current() async -> PacketFilterPolicy {
        loadedPolicy
    }

    public func apply(_ policy: PacketFilterPolicy) async throws(DaemonFailure) {
        try await slot.acquirePort(); defer { slot.release() }
        #if WGEX_LAB_BUILD
            defer { DaemonDiagnostics.verifier(verificationStatus) }
        #endif
        verificationStatus = .unknown
        loadedText = nil
        do {
            let (phase, effectiveModifiers, effectiveContext) = try model(for: policy)
            let text = try PacketFilterRenderer.render(phase: phase, modifiers: effectiveModifiers, context: effectiveContext)
            if needsReferenceCheck || (!text.isEmpty && token == nil) {
                try await loadBlockingReplacement()
            }
            if !stockCheckedForApply, canaryProbe == nil || token == nil || needsReferenceCheck {
                try await verifyStockAnchor()
            }
            stockCheckedForApply = false
            try await verifyRestoredToken()
            if !text.isEmpty, token == nil {
                token = try await lifecycle.acquire()
            }
            let reloaded = try await loadTransition(text)
            if !text.isEmpty {
                try await runner.verifyTunnelTable(effectiveContext)
            }
            try await updateStateKills(phase: phase, context: effectiveContext, modifiers: effectiveModifiers, enforcing: !text.isEmpty)
            if text.isEmpty, let owned = token {
                try await lifecycle.release(owned)
                token = nil
            }
            try await completeApply(policy, text: text, reloaded: reloaded)
        } catch let failure as DaemonFailure where failure.kind == .pfCanaryFailed {
            appliedText = nil; verificationStatus = .unknown
            throw failure
        } catch DaemonFailure.pfDeadline {
            appliedText = nil; verificationStatus = .unknown
            throw .portTimedOut
        } catch let failure as DaemonFailure where failure.kind == .pfProcess {
            let code = failure.systemStatus ?? 5
            appliedText = nil; verificationStatus = .unknown
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(DaemonFailure.pfProcess(code), context: "pf apply")
            #endif
            throw .portSystem(code: code)
        } catch {
            appliedText = nil; verificationStatus = .unknown
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(error, context: "pf apply")
            #endif
            throw .portSystem(code: 5)
        }
    }

    /// Called with a baseline captured before the liveness monitor sends its canary.
    /// A read-back change, missing stock anchor or non-incrementing counter invalidates trust.
    public func verifyCanary(after baseline: UInt64) async throws -> UInt64 {
        try await slot.acquire(); defer { slot.release() }
        #if WGEX_LAB_BUILD
            defer { DaemonDiagnostics.verifier(verificationStatus) }
        #endif
        guard let loadedText, !loadedText.isEmpty else {
            verificationStatus = .unknown
            throw DaemonFailure.pfVerification
        }
        verificationStatus = .unknown
        do { return try await measureCanary(after: baseline, checkingEnabled: true) }
        catch { appliedText = nil; throw error }
    }

    public func verification() async -> PFVerificationStatus {
        verificationStatus
    }

    public func configureProfile(_ profile: TunnelProfile) async throws {
        try await slot.acquire(); defer { slot.release() }
        self.profile = profile
    }

    public func setModifiers(_ modifiers: PolicyModifiers) async throws {
        try await slot.acquire(); defer { slot.release() }
        verificationStatus = .unknown
        underlayIdentity = PFUnderlayIdentity(modifiers.underlay)
        guard let name = primaryInterface(modifiers.underlay)
        else { return try configureNoUnderlay(modifiers) }
        let dns = try (profile?.interface.dns ?? []).map { try PFAddress($0.stringRepresentation) }
        let ranges = (profile?.interface.addresses ?? []) + (profile?.peers.flatMap(\.allowedIPs) ?? [])
        let ipv6Policy = profile?.protection.ipv6Policy ?? .tunnel
        let lanDNS = dns.filter { address in
            !ranges.contains { $0.contains(address.range) } && modifiers.underlay.lanSubnets.contains { $0.contains(address.range) }
        }
        let nextContext = try PFContext(
            underlay: PFInterface(name), resolvers: modifiers.underlay.resolvers.map(PFAddress.init),
            tunnelDNS: dns.filter { !lanDNS.contains($0) }, lanTunnelDNS: lanDNS,
            lanSubnets: modifiers.underlay.lanSubnets, tunnelRanges: ranges, consoleUID: modifiers.consoleUID ?? context.consoleUID,
        )
        try configureContext(preserveLabContext(nextContext, original: context), modifiers: PFModifiers(
            allowLAN: modifiers.allowLAN, captiveWindow: modifiers.captiveWindow != nil,
            ipv6Policy: ipv6Policy,
            ipv6Underlay: modifiers.underlay.interfaceV6Name.map(PFInterface.init),
            canary: PFCanaryFamily.choose(modifiers.underlay), exclusions: modifiers.exclusions,
            exclusionPorts: modifiers.exclusionPorts,
        ))
    }

    private func configureNoUnderlay(_ modifiers: PolicyModifiers) throws {
        let next = try PFContext(underlay: PFInterface("lo0"), consoleUID: modifiers.consoleUID ?? context.consoleUID)
        try configureContext(preserveLabContext(next, original: context), modifiers: PFModifiers(canary: .loopback))
    }

    public func acquireToken(existing: String?) async throws -> String {
        try await slot.acquire(); defer { slot.release() }
        let replacing = needsReferenceCheck || token == nil
        if replacing {
            try await loadBlockingReplacement()
        }
        if !replacing, try await !runner.isEnabled() {
            try await loadBlockingReplacement()
        }
        try await verifyStockAnchor()
        stockCheckedForApply = true
        try await verifyRestoredToken()
        token = try await lifecycle.acquire()
        guard let token else { throw DaemonFailure.pfToken }
        return token
    }

    public func releaseToken(_ owned: String) async throws {
        try await slot.acquire(); defer { slot.release() }
        // Empty-anchor apply already releases the reference; never release it twice.
        guard let token else { return }
        guard token == owned, loadedPolicy == .disconnected, verificationStatus == .unprotected else {
            throw DaemonFailure.pfToken
        }
        try await lifecycle.release(token)
        self.token = nil
    }

    public func verifyEvaluation() async throws {
        try await slot.acquire(); defer { slot.release() }
        #if WGEX_LAB_BUILD
            defer { DaemonDiagnostics.verifier(verificationStatus) }
        #endif
        guard loadedPolicy != .disconnected else { return }
        guard let loadedText, !loadedText.isEmpty else { throw DaemonFailure.pfVerification }
        verificationStatus = .unknown
        guard let canaryProbe else {
            verificationStatus = .unknown
            throw DaemonFailure.integrationNotImplemented("pf canary sender")
        }
        do {
            let baseline = canaryBaseline
            referenceTick = (referenceTick + 1) % 6
            if referenceTick == 0 {
                token = try await lifecycle.reconcile(force: true)
                guard token != nil else { throw DaemonFailure.pfToken }
            }
            try await sendCanary(canaryProbe)
            _ = try await measureCanary(after: baseline, checkingEnabled: referenceTick != 0)
        } catch {
            appliedText = nil; verificationStatus = .unknown
            throw error
        }
    }

    /// Used at startup and external release before any ownership query or enabling operation.
    private func loadBlockingReplacement() async throws {
        verificationStatus = .unknown
        let safeModifiers = PFModifiers(allowLAN: false, ipv6Underlay: modifiers.ipv6Underlay, canary: modifiers.canary)
        let text = try PacketFilterRenderer.render(phase: .error, modifiers: safeModifiers, context: context)
        try await runner.load(text)
        loadedPolicy = .error; loadedText = text; appliedText = text
        loadedCanonical = PacketFilterReadback.canonical(text); canaryBaseline = 0; recoveryStep(.rendered)
    }

    /// Re-acquires a disappeared reference; the diagnostic callback is emitted once per daemon lifetime.
    public func repairLiveness() async throws -> String {
        try await slot.acquire(); defer { slot.release() }
        token = try await lifecycle.reconcile(force: true)
        if token == nil {
            try await loadBlockingReplacement()
            token = try await lifecycle.acquire()
        }
        if try await !runner.isEnabled() {
            try await runner.command(["-e"])
        }
        guard let token, try await runner.isEnabled() else { throw DaemonFailure.pfVerification }
        return token
    }

    private func verifyStockAnchor() async throws {
        let main = try await runner.command(["-s", "rules"])
        guard PacketFilterReadback.stockAnchorPresent(main.stdout) else {
            siblingAnchors = try await runner.command(["-a", "com.apple", "-s", "Anchors", "-v"]).stdout
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.verificationFailure(.anchorMissing)
                DaemonDiagnostics.log(DaemonFailure.pfVerification, context: "pf stock anchor")
            #endif
            throw DaemonFailure.pfVerification
        }
    }

    private func verifyRestoredToken() async throws {
        guard needsReferenceCheck else { return }
        token = try await lifecycle.reconcile()
        needsReferenceCheck = false
    }
}

private func preserveLabContext(_ next: PFContext, original context: PFContext) -> PFContext {
    #if WGEX_LAB_BUILD
        var result = next
        result.labEscapeHatch = context.labEscapeHatch
        return result
    #else
        return next
    #endif
}

private func killIPv6States(runner: PFCtl, modifiers: PFModifiers, primary: PFInterface) async throws {
    if let ipv6 = modifiers.ipv6Underlay, ipv6 != primary {
        try await runner.killStates(.interface(ipv6))
    }
}

private func primaryInterface(_ underlay: UnderlaySnapshot) -> String? {
    guard underlay.v4 != nil || underlay.v6 != nil else { return nil }
    switch PFCanaryFamily.choose(underlay) {
    case .ipv4: return underlay.interfaceV4Name ?? underlay.interfaceNames.first
    case .ipv6: return underlay.interfaceV6Name ?? underlay.interfaceNames.first
    case .loopback: return nil
    }
}

private extension PolicyEnforcer {
    private func completeApply(_ policy: PacketFilterPolicy, text: String, reloaded: Bool) async throws {
        loadedPolicy = policy; loadedText = text
        loadedCanonical = PacketFilterReadback.canonical(text)
        if reloaded {
            canaryBaseline = 0
        }
        verificationStatus = text.isEmpty ? .unprotected : .rulesVerified
        if !text.isEmpty, let canaryProbe {
            try await sendCanary(canaryProbe)
            _ = try await measureCanary(after: canaryBaseline, checkingEnabled: false)
        }
    }

    /// A positive canary measures both the calling stock anchor and the loaded ordered rules.
    func loadTransition(_ text: String) async throws -> Bool {
        if !text.isEmpty, canaryProbe != nil, text == appliedText {
            recoveryStep(.kept)
            return false
        }
        appliedText = nil
        if !text.isEmpty, canaryProbe != nil {
            try await runner.command(["-o", "none", "-n", "-a", PacketFilterRenderer.anchor, "-f", "-"], input: text)
            try await runner.command(["-o", "none", "-a", PacketFilterRenderer.anchor, "-f", "-"], input: text)
        } else {
            try await runner.load(text)
        }
        appliedText = text
        recoveryStep(.rendered)
        return true
    }

    /// Names the crash-recovery anchor step in Lab builds; the first verified measurement ends the recovery (M1-20).
    func recoveryStep(_ step: DaemonDiagnostics.RecoveryStep) {
        guard recovering else { return }
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.recovery(step)
        #endif
        if step == .verified {
            recovering = false
        }
    }

    func sendCanary(_ probe: @Sendable () async throws -> Void) async throws {
        do { try await probe() }
        catch { throw DaemonFailure(code: .pfCanaryFailed) }
    }

    func measureCanary(after baseline: UInt64, checkingEnabled: Bool) async throws -> UInt64 {
        let readback = try await runner.command(["-a", PacketFilterRenderer.anchor, "-vsr"])
        guard PacketFilterReadback.canonical(readback.stdout) == loadedCanonical else { throw DaemonFailure.pfVerification }
        if checkingEnabled, try await !runner.isEnabled() {
            throw DaemonFailure.pfVerification
        }
        let count = try PacketFilterReadback.canaryEvaluations(readback.stdout)
        guard count > baseline else { throw DaemonFailure.pfVerification }
        canaryBaseline = count
        recoveryStep(.verified)
        switch loadedPolicy {
        case .connected: verificationStatus = .protected
        case .captiveWindow: verificationStatus = .captiveWindow
        default: verificationStatus = .blocked
        }
        return count
    }

    func updateStateKills(phase: PFPhase, context: PFContext, modifiers: PFModifiers, enforcing: Bool) async throws {
        let interfaces = Set([context.underlay] + [modifiers.ipv6Underlay].compactMap(\.self))
        let blocking = enforcing && !modifiers.captiveWindow && phase != .disconnecting
        if blocking, blockingInterfaces.isEmpty || blockingInterfaces != interfaces || blockingUnderlayIdentity != underlayIdentity {
            try await runner.killStates(.interface(context.underlay))
            try await killIPv6States(runner: runner, modifiers: modifiers, primary: context.underlay)
        }
        if blocking {
            blockingInterfaces = interfaces; blockingUnderlayIdentity = underlayIdentity
        } else if !enforcing || modifiers.captiveWindow {
            blockingInterfaces = []; blockingUnderlayIdentity = nil
        }
    }

    func model(for policy: PacketFilterPolicy) throws -> (PFPhase, PFModifiers, PFContext) {
        let phase: PFPhase
        var resolvers = context.resolvers, endpoints = context.endpoints, tunnel = context.tunnel
        var captive = false
        switch policy {
        case .disconnected: phase = .disconnected
        case let .connecting(addresses, candidates):
            phase = .connecting; resolvers = try addresses.map(PFAddress.init); endpoints = try candidates.map(PFEndpoint.init)
        case let .connected(interface, candidates):
            phase = .connected; tunnel = try PFInterface(interface); endpoints = try candidates.map(PFEndpoint.init)
        case .disconnecting: phase = .disconnecting
        case .error: phase = .error
        case .lockdown: phase = .lockdown
        case let .captiveWindow(expires):
            guard expires > Date() else { throw DaemonFailure.pfInvalidInput("expired captive window") }
            phase = .error; captive = true
        }
        let effective = try PFContext(
            underlay: context.underlay,
            tunnel: tunnel,
            endpoints: endpoints,
            resolvers: resolvers,
            tunnelDNS: context.tunnelDNS,
            lanTunnelDNS: context.lanTunnelDNS,
            lanSubnets: context.lanSubnets,
            tunnelRanges: context.tunnelRanges,
            consoleUID: context.consoleUID,
        )
        return (phase, PFModifiers(
            allowLAN: modifiers.allowLAN, captiveWindow: captive,
            ipv6Policy: modifiers.ipv6Policy, appleServices: modifiers.appleServices,
            ipv6Underlay: modifiers.ipv6Underlay, canary: modifiers.canary, exclusions: modifiers.exclusions,
            exclusionPorts: modifiers.exclusionPorts,
        ), preserveLabContext(effective, original: context))
    }
}
