// SPDX-License-Identifier: MIT

import CryptoKit
import Foundation
import WGEXCore
import WGEXDaemonProtocol

public enum PacketFilterRenderer {
    public static let anchor = "com.apple/wgex"
    public static let canaryLabel = "wgex-canary"

    public static func rules(phase: PFPhase, modifiers: PFModifiers, context: PFContext) throws -> [PFRule] {
        if phase == .disconnected, !modifiers.captiveWindow {
            return []
        }
        if phase == .connected, !modifiers.captiveWindow, context.tunnel == nil {
            throw DaemonFailure.pfInvalidInput("connected tunnel")
        }
        if let apple = modifiers.appleServices, phase == .connected, apple.tunnel != context.tunnel {
            throw DaemonFailure.pfInvalidInput("Apple services tunnel")
        }
        var builder = PFRuleBuilder(context: context, modifiers: modifiers)
        #if WGEX_LAB_BUILD
            if let host = context.labEscapeHatch {
                // Lab escape hatch (26 Oct 2026: a blocked guest stranded the lab twice). The leak verdicts
                // record this one TCP/22 exception for the hypervisor's host-only address.
                builder.add(
                    .pass,
                    .inbound,
                    on: modifiers.canary == .loopback ? nil : context.underlay,
                    proto: .tcp,
                    from: .literal(host.text),
                    port: 22,
                    state: false,
                )
                builder.add(
                    .pass,
                    .outbound,
                    on: modifiers.canary == .loopback ? nil : context.underlay,
                    proto: .tcp,
                    sourcePort: 22,
                    to: .literal(host.text),
                    state: false,
                )
            }
        #endif
        try builder.transport(phase: phase)
        builder.dns(phase: phase)
        builder.dhcpAndNDP()
        builder.exclusions()
        builder.exclusionPorts()
        builder.pmtuAndTunnelRanges()
        builder.ipv6AndAppleServices(phase: phase)
        builder.windowsAndLAN()
        builder.add(.block)
        return IPv6PolicyRules.underlays(builder.rules, primary: context.underlay, ipv6: modifiers.ipv6Underlay)
    }

    public static func render(phase: PFPhase, modifiers: PFModifiers, context: PFContext) throws -> String {
        var lines = try rules(phase: phase, modifiers: modifiers, context: context).map(render)
        if !lines.isEmpty, !context.tunnelRanges.isEmpty {
            let ranges = context.tunnelRanges.map(\.stringRepresentation).joined(separator: ", ")
            lines.insert("table <\(tunnelTable(context))> const { \(ranges) }", at: 0)
        }
        return lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
    }

    /// The constant table name binds read-back rules to their validated range set.
    package static func tunnelTable(_ context: PFContext) -> String {
        let text = context.tunnelRanges.map(\.stringRepresentation).joined(separator: ", ")
        let digest = SHA256.hash(data: Data(text.utf8)).prefix(8).map { String(format: "%03d", $0) }.joined()
        return "wgex_" + digest
    }

    public static func render(_ rule: PFRule) -> String {
        var parts = [rule.action.rawValue]
        if let direction = rule.direction {
            parts.append(direction.rawValue)
        }
        parts.append("quick")
        if let interface = rule.interface {
            parts += ["on", interface.name]
        }
        if let tunnel = rule.routeTo {
            parts += ["route-to", "(\(tunnel.name))"]
        }
        if let family = rule.family {
            parts.append(family.rawValue)
        }
        if let proto = rule.proto {
            parts += ["proto", proto.rawValue]
        }
        return (parts + addresses(rule) + options(rule)).joined(separator: " ")
    }

    private static func addresses(_ rule: PFRule) -> [String] {
        if rule.source == .any, rule.destination == .any, rule.sourcePort == nil, rule.destinationPort == nil {
            return ["all"]
        }
        var parts = ["from", rule.source.text]
        if let port = rule.sourcePort {
            parts += ["port", portText(port, rule.sourcePortEnd)]
        }
        parts += ["to", rule.destination.text]
        if let port = rule.destinationPort {
            parts += ["port", portText(port, rule.destinationPortEnd)]
        }
        return parts
    }

    /// `1911`, or `6881:6889` for an inclusive range (pf's `:` operator, which pfctl prints back unchanged).
    private static func portText(_ port: UInt16, _ end: UInt16?) -> String {
        guard let end, end != port else { return String(port) }
        return "\(port):\(end)"
    }

    private static func options(_ rule: PFRule) -> [String] {
        var parts: [String] = []
        if let uid = rule.uid {
            parts += ["user", String(uid)]
        }
        if rule.label == "wgex-resolver" {
            parts += ["group", "=", String(ResolverThreadIdentity.gid)]
        }
        if let type = rule.icmpType {
            parts += [rule.proto == .icmp6 ? "icmp6-type" : "icmp-type", String(type)]
            if rule.proto == .icmp {
                parts += ["code", "4"]
            }
        }
        if rule.action == .pass {
            if rule.keepState, rule.proto == .tcp {
                parts += ["flags", "S/SA"]
            }
            parts.append(rule.keepState ? "keep state" : "no state")
        }
        if let label = rule.label {
            parts += ["label", "\"\(label)\""]
        }
        return parts
    }
}

private struct PFRuleBuilder {
    let context: PFContext
    let modifiers: PFModifiers
    var rules: [PFRule] = []
    var underlay: PFInterface {
        context.underlay
    }

    mutating func add(
        _ action: PFRule.Action = .pass, _ direction: PFRule.Direction? = nil,
        on interface: PFInterface? = nil, family: PFRule.Family? = nil,
        proto: PFRule.ProtocolName? = nil, from source: PFRule.Address = .any, sourcePort: UInt16? = nil,
        to destination: PFRule.Address = .any, port: UInt16? = nil, uid: UInt32? = nil,
        icmp: UInt8? = nil, state: Bool = false, label: String? = nil,
    ) {
        var rule = PFRule(action)
        rule.direction = direction; rule.interface = interface; rule.family = family; rule.proto = proto
        let literals = [source, destination].compactMap { address -> String? in
            if case let .literal(value) = address, !value.hasPrefix("<") {
                return value
            }
            return nil
        }
        if family == nil, let literal = literals.first {
            rule.family = literal.contains(":") ? .ipv6 : .ipv4
        }
        rule.source = source; rule.sourcePort = sourcePort; rule.destination = destination; rule.destinationPort = port
        rule.uid = uid; rule.icmpType = icmp; rule.keepState = state; rule.label = label
        rules.append(rule)
    }

    mutating func transport(phase: PFPhase) throws {
        if modifiers.canary == .loopback {
            addCanary()
        }
        try add(on: PFInterface("lo0"))
        if phase == .connected, !modifiers.captiveWindow, let tunnel = context.tunnel {
            add(.pass, .outbound, on: tunnel); add(.pass, .inbound, on: tunnel)
        }
        // Before endpoint or LAN passes, including on a documentation subnet.
        if modifiers.canary != .loopback {
            addCanary()
        }
        if phase == .connecting || phase == .connected, !modifiers.captiveWindow {
            for endpoint in context.endpoints {
                add(
                    .pass,
                    .outbound,
                    on: underlay,
                    proto: endpoint.transport == .udp ? .udp : .tcp,
                    to: .literal(endpoint.address.text),
                    port: endpoint.port,
                    uid: 0,
                    state: true,
                )
            }
        }
    }

    mutating func addCanary() {
        add(
            .block,
            .outbound,
            on: underlay,
            proto: .udp,
            to: .literal(modifiers.canary.address),
            port: 9,
            uid: 0,
            label: PacketFilterRenderer.canaryLabel,
        )
    }

    mutating func dns(phase: PFPhase) {
        for resolver in context.resolvers {
            for proto in [PFRule.ProtocolName.udp, .tcp] {
                add(
                    .pass,
                    .outbound,
                    on: underlay,
                    proto: proto,
                    to: .literal(resolver.text),
                    port: 53,
                    uid: 0,
                    state: true,
                    label: "wgex-resolver",
                )
                if modifiers.captiveWindow {
                    // System DNS may be emitted by mDNSResponder rather than the console uid.
                    add(.pass, .outbound, on: underlay, proto: proto, to: .literal(resolver.text), port: 53, state: true)
                }
            }
        }
        if phase == .connected, !modifiers.captiveWindow {
            for address in context.tunnelDNS {
                dnsPass(address, on: context.tunnel)
            }
            for address in context.lanTunnelDNS {
                dnsPass(address, on: underlay)
            }
        }
        for proto in [PFRule.ProtocolName.tcp, .udp] {
            for port: UInt16 in [53, 853] {
                add(.block, .outbound, proto: proto, port: port)
            }
        }
    }

    mutating func dnsPass(_ address: PFAddress, on interface: PFInterface?) {
        for proto in [PFRule.ProtocolName.udp, .tcp] {
            add(.pass, .outbound, on: interface, proto: proto, to: .literal(address.text), port: 53)
        }
    }

    var infrastructureInterface: PFInterface? {
        modifiers.canary == .loopback ? nil : underlay
    }

    mutating func dhcpAndNDP() {
        add(
            .pass,
            .outbound,
            on: infrastructureInterface,
            family: .ipv4,
            proto: .udp,
            sourcePort: 68,
            to: .literal("255.255.255.255"),
            port: 67,
        )
        for subnet in context.lanSubnets where !subnet.isIPv6 {
            add(
                .pass,
                .outbound,
                on: infrastructureInterface,
                proto: .udp,
                sourcePort: 68,
                to: .literal(subnet.stringRepresentation),
                port: 67,
            )
        }
        add(.pass, .inbound, on: infrastructureInterface, family: .ipv4, proto: .udp, sourcePort: 67, port: 68)
        add(
            .pass,
            .outbound,
            on: infrastructureInterface,
            proto: .udp,
            from: .literal("fe80::/10"),
            sourcePort: 546,
            to: .literal("ff02::1:2"),
            port: 547,
        )
        add(
            .pass,
            .inbound,
            on: infrastructureInterface,
            proto: .udp,
            from: .literal("fe80::/10"),
            sourcePort: 547,
            to: .literal("fe80::/10"),
            port: 546,
        )
        for source in ["fe80::/10", "::"] {
            for destination in ["fe80::/10", "ff02::/16"] {
                for type: UInt8 in [133, 134, 135, 136] {
                    add(on: infrastructureInterface, proto: .icmp6, from: .literal(source), to: .literal(destination), icmp: type)
                }
            }
        }
    }

    /// Excluded destinations (DEC-087) pass on the physical interface without state: outbound to the range and inbound
    /// from it. Each pass carries its direction, so a range that contains the physical address never lets that address
    /// send to a destination outside the exclusions (M08-R01 F1). They follow the DNS blocks, so port 53 and 853 to an
    /// excluded address stay blocked, and precede the tunnel-range and outside-IPv6 blocks, so an exclusion inside
    /// AllowedIPs still leaves outside the tunnel.
    mutating func exclusions() {
        guard modifiers.canary != .loopback else { return }
        for range in modifiers.exclusions {
            add(.pass, .outbound, on: underlay, to: .literal(range.stringRepresentation))
            add(.pass, .inbound, on: underlay, from: .literal(range.stringRepresentation))
        }
    }

    /// Excluded local ports (DEC-126) for apps that bind to the physical interface: outbound from that interface's own
    /// addresses and inbound to them, per family and transport, without state like the LAN and exclusion passes. No state
    /// means removing a port, switching tunnel or losing the intended tunnel revokes the pass on the next load; the
    /// enforcer flushes states only on interface changes, so a keep-state pass could outlive its exclusion. A packet
    /// sourced from the tunnel address never matches `(underlay)`, so it stays blocked on the physical interface. Same
    /// position as the address exclusions: after the DNS blocks, before the tunnel-range and outside-IPv6 blocks.
    mutating func exclusionPorts() {
        guard modifiers.canary != .loopback else { return }
        for family in [PFRule.Family.ipv4, .ipv6] {
            for entry in modifiers.exclusionPorts {
                for transport in entry.transports {
                    let proto: PFRule.ProtocolName = transport == .tcp ? .tcp : .udp
                    add(
                        .pass,
                        .outbound,
                        on: underlay,
                        family: family,
                        proto: proto,
                        from: .interfaceAddress(underlay),
                        sourcePort: entry.lower,
                    )
                    rules[rules.count - 1].sourcePortEnd = entry.upper
                    add(
                        .pass,
                        .inbound,
                        on: underlay,
                        family: family,
                        proto: proto,
                        to: .interfaceAddress(underlay),
                        port: entry.lower,
                    )
                    rules[rules.count - 1].destinationPortEnd = entry.upper
                }
            }
        }
    }

    mutating func pmtuAndTunnelRanges() {
        for address in Set(context.endpoints.map(\.address)).sorted() {
            add(
                .pass,
                .inbound,
                on: underlay,
                proto: address.isIPv6 ? .icmp6 : .icmp,
                from: .literal(address.text),
                icmp: address.isIPv6 ? 2 : 3,
            )
        }
        if !context.tunnelRanges.isEmpty {
            let family: PFRule.Family? = context.tunnelRanges.allSatisfy { !$0.isIPv6 } ? .ipv4
                : (context.tunnelRanges.allSatisfy(\.isIPv6) ? .ipv6 : nil)
            add(.block, .outbound, on: underlay, family: family, to: .literal("<\(PacketFilterRenderer.tunnelTable(context))>"))
        }
    }

    mutating func windowsAndLAN() {
        if modifiers.captiveWindow {
            for port: UInt16 in [80, 443] {
                add(
                    .pass,
                    .outbound,
                    on: underlay,
                    proto: .tcp,
                    port: port,
                    uid: context.consoleUID,
                    state: true,
                )
            }
        }
        if modifiers.allowLAN {
            for subnet in context.lanSubnets {
                add(on: underlay, from: .literal(subnet.stringRepresentation), to: .literal(subnet.stringRepresentation))
            }
            for destination in ["169.254.0.0/16", "224.0.0.0/24", "255.255.255.255", "fe80::/10", "ff02::/16"] {
                add(on: underlay, to: .literal(destination))
            }
        }
    }

    mutating func ipv6AndAppleServices(phase: PFPhase) {
        // Infrastructure and tunnel-range blocks precede outside-family passes; DNS stays blocked.
        if modifiers.ipv6Policy == .blockOutside {
            add(.block, .outbound, on: underlay, family: .ipv6)
        }
        if phase == .connected, !modifiers.captiveWindow, let apple = modifiers.appleServices {
            for destination in apple.destinations {
                add(.pass, .outbound, on: underlay, to: .literal(destination.stringRepresentation))
                rules[rules.count - 1].routeTo = apple.tunnel
            }
        }
        if modifiers.ipv6Policy == .allowOutside, !modifiers.captiveWindow {
            add(.pass, .outbound, on: underlay, family: .ipv6, state: true)
        }
    }
}

/// DNS and MTU observations do not themselves invalidate established LAN states.
package struct PFUnderlayIdentity: Equatable {
    package let v4: UInt32?
    package let v6: UInt32?
    package let names: [String]
    package let primary4: String?
    package let primary6: String?
    package init(_ value: UnderlaySnapshot) {
        v4 = value.v4; v6 = value.v6; names = value.interfaceNames.sorted()
        primary4 = value.interfaceV4Name; primary6 = value.interfaceV6Name
    }
}
