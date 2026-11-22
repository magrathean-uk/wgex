// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Tunnel exclusions (DEC-087). Excluded ranges are carved out of the tunnel's routes, so their traffic follows the
/// system's default route on the physical interface, and the packet filter passes them there as it passes LAN ranges.
/// Host names resolve on the physical resolvers (the endpoint resolver) at activation, and again on network change and
/// reconnect; a name that does not resolve stays in the tunnel and is reported in `TunnelStatus.unresolvedExclusions`.
package extension TunnelController {
    /// The whole lookup of every excluded name shares this much awake time; it never fails a start.
    static let exclusionResolutionSeconds = 5

    /// The ranges the packet filter passes: only for the intended tunnel whose profile the policy port holds (as
    /// `policyAllowsLAN`), so a lockdown with no intended tunnel never passes a former tunnel's exclusions.
    var policyExclusions: [IPAddressRange] {
        guard let profileID = intended?.profileID ?? journal.snapshot().intent?.profileID,
              policyProfileID == profileID, exclusionState.profileID == profileID else { return [] }
        return exclusionState.ranges
    }

    /// The local ports the packet filter passes (DEC-126), bound to the intended tunnel's profile as `policyExclusions`.
    var policyExclusionPorts: [PortExclusion] {
        guard let profileID = intended?.profileID ?? journal.snapshot().intent?.profileID,
              policyProfileID == profileID, exclusionState.profileID == profileID else { return [] }
        return exclusionState.ports
    }

    /// The tunnel's routes: AllowedIPs (plus ::/0 for blockOutside without IPv6 routes) less the excluded ranges
    /// (DEC-087), with a default route split into halves. Excluded destinations then follow the system's own default route
    /// on the physical interface; no route names the physical gateway, so a gateway change needs no route change.
    static func routes(_ profile: TunnelProfile, interfaceName: String, excluding exclusions: [IPAddressRange] = []) -> [RouteSpec] {
        var ranges = profile.peers.flatMap(\.allowedIPs)
        if profile.protection.ipv6Policy == .blockOutside, !ranges.contains(where: \.isIPv6) {
            ranges.append(.allIPv6)
        }
        var routes: [RouteSpec] = []
        for range in TunnelExclusions.carve(ranges, excluding: exclusions) {
            if range.networkPrefixLength == 0 {
                let addresses = range.isIPv6 ? ["::", "8000::"] : ["0.0.0.0", "128.0.0.0"]
                routes += addresses.map { RouteSpec(destination: $0, prefixLength: 1, interfaceName: interfaceName) }
            } else {
                routes.append(RouteSpec(
                    destination: range.network.address,
                    prefixLength: range.networkPrefixLength,
                    interfaceName: interfaceName,
                ))
            }
        }
        return Array(Set(routes)).sorted { ($0.destination, $0.prefixLength) < ($1.destination, $1.prefixLength) }
    }

    /// The ranges a route plan for `profile` removes: the resolved state when it belongs to this profile, else the literals.
    func exclusionRanges(for profile: TunnelProfile) -> [IPAddressRange] {
        exclusionState.profileID == profile.id ? exclusionState.ranges : profile.exclusions.effectiveRanges()
    }

    /// Resolves the profile's excluded host names and records the result for the policy, routes and status.
    func resolveExclusions(_ profile: TunnelProfile, generation: Generation) async throws {
        let names = profile.exclusions.hostNames
        let found: [String: [IPAddressRange]] = names.isEmpty ? [:] : await lookUpExclusions(names)
        try check(generation)
        exclusionState = Self.exclusionState(profile, found: found)
        snapshot.unresolvedExclusions = exclusionState.unresolved
    }

    /// Re-resolves the excluded host names on a network change or reconnect and replaces the tunnel routes that changed.
    /// Skipped during a captive window, which keeps its withdrawn routes, and before the tunnel interface exists.
    func refreshExclusions(_ profile: TunnelProfile, generation: Generation) async throws {
        guard !profile.exclusions.hostNames.isEmpty, journal.snapshot().captiveWindow == nil,
              let identity = resource(generation).identity else { return }
        try await resolveExclusions(profile, generation: generation)
        let next = Self.routes(profile, interfaceName: identity.name, excluding: exclusionState.ranges)
        try await replaceTunnelRoutes(next, generation: generation)
        publish()
    }

    /// Installs the new routes before removing the stale ones, so no destination is ever without a tunnel route between
    /// the two (every route is a utun route with its own destination and prefix). The canary route is kept as it is.
    func replaceTunnelRoutes(_ next: [RouteSpec], generation: Generation) async throws {
        var resources = resource(generation)
        let canary = resources.canaryRoute?.routes ?? []
        let current = resources.routes.filter { !canary.contains($0) }
        let added = next.filter { !current.contains($0) }
        let stale = current.filter { !next.contains($0) }
        guard !added.isEmpty || !stale.isEmpty else { return }
        resources.routes = canary + current + added
        try updateResource(resources, generation: generation)
        try await ports.routes.install(added, generation: generation)
        try check(generation)
        if !stale.isEmpty {
            try await ports.routes.removeRoutes(stale, of: generation)
            try check(generation)
        }
        resources = resource(generation)
        resources.routes = canary + next
        try updateResource(resources, generation: generation)
    }

    /// The state for `profile` given the addresses each name resolved to. Resolved addresses that touch the tunnel's own
    /// addresses or DNS servers are dropped; when the carved plan would exceed the route limit, only the literals apply
    /// and every name is reported unresolved.
    static func exclusionState(_ profile: TunnelProfile, found: [String: [IPAddressRange]]) -> ExclusionResolutionState {
        let own = profile.interface.addresses.map(\.network) + profile.interface.dns.map(\.address)
        var state = ExclusionResolutionState(
            profileID: profile.id, literal: profile.exclusions.effectiveRanges(), ports: profile.exclusions.ports,
        )
        for name in profile.exclusions.hostNames {
            let usable = (found[name] ?? []).filter { address in !own.contains { $0.overlaps(address) } }
            if usable.isEmpty {
                state.unresolved.append(name)
            }
            state.resolved += usable
        }
        state.resolved = Array(Set(state.resolved)).sorted()
        if routes(profile, interfaceName: "utun0", excluding: state.ranges).count > 4096 {
            state.resolved = []; state.unresolved = profile.exclusions.hostNames
        }
        return state
    }

    /// Looks every name up concurrently within `exclusionResolutionSeconds`; on the deadline every name counts as
    /// unresolved. At most `TunnelExclusions.maximumAddressesPerHost` literal addresses per name.
    private func lookUpExclusions(_ names: [String]) async -> [String: [IPAddressRange]] {
        let resolver = ports.resolver, underlay = underlay
        let task = Task { await Self.lookUp(names, resolver: resolver, underlay: underlay) }
        let result: Result<[String: [IPAddressRange]], any Error> = await withCheckedContinuation { continuation in
            let completion = ControllerCompletion(continuation)
            let deadline = Task { [operationClock] in
                do {
                    try await operationClock.sleep(for: .seconds(Self.exclusionResolutionSeconds)); try Task.checkCancellation()
                    guard let waiter = completion.take() else { return }
                    task.cancel(); waiter.resume(returning: .failure(DaemonFailure.portTimedOut))
                } catch { /* A completed lookup cancels this deadline. */ }
            }
            Task {
                let found = await task.value
                guard let waiter = completion.take() else { return }
                deadline.cancel(); waiter.resume(returning: .success(found))
            }
        }
        return (try? result.get()) ?? [:]
    }

    private static func lookUp(
        _ names: [String], resolver: any DaemonUnderlayResolving, underlay: UnderlaySnapshot,
    ) async -> [String: [IPAddressRange]] {
        await withTaskGroup(of: (String, [IPAddressRange]).self) { group in
            for name in names {
                group.addTask {
                    let answers = await (try? resolver.resolve(host: name, underlay: underlay)) ?? []
                    let ranges = UnderlayResolver.validLiterals(answers).compactMap { try? IPAddressRange($0) }
                    return (name, Array(ranges.prefix(TunnelExclusions.maximumAddressesPerHost)))
                }
            }
            var found: [String: [IPAddressRange]] = [:]
            for await (name, ranges) in group {
                found[name] = ranges
            }
            return found
        }
    }
}
