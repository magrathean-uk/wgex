// SPDX-License-Identifier: MIT
#if WGEX_LAB_BUILD
    import Foundation
    import os
    import WGEXCore
    import WGEXDaemonProtocol

    extension DaemonDiagnostics {
        /// Optional task-scoped observation of the same public lines sent to unified logging.
        @TaskLocal package static var publicLineObserver: (@Sendable (String) -> Void)?

        /// Ownership transitions contain no token, PID, boot identity or other dynamic data.
        package enum TokenEvent: String, Sendable {
            case acquired = "token acquired"
            case released = "token released"
            case recovered = "token recovered"
            case referenceLeaked = "reference leaked"
        }

        /// Failure verdicts known at the stock-anchor and reference-release boundaries.
        package enum VerificationFailure: String, Sendable {
            case anchorMissing, referenceLeaked
        }

        /// Called only after the ordinary diagnostics adapter admits a changed status.
        public static func status(_ status: TunnelStatus) {
            let labels = phase(status.phase)
            emit("status: phase=" + labels.phase + " protection=" + protection(status.protection) + " reason=" + labels.reason)
        }

        package static func verifier(_ verdict: PFVerificationStatus) {
            emit("verifier: " + verdict.rawValue)
        }

        package static func verificationFailure(_ verdict: VerificationFailure) {
            emit("verifier: " + verdict.rawValue)
        }

        package static func token(_ event: TokenEvent) {
            emit("pf: " + event.rawValue)
        }

        /// Fixed text naming the recovery step; never policy text, token or interface data (M1-20).
        package static func recovery(_ step: RecoveryStep) {
            emit("recovery: " + (recoveryLabels[step] ?? "unknown"))
        }

        /// Every step has a label; the Lab test `M1-20 recovery labels are fixed text` checks it.
        package static let recoveryLabels: [RecoveryStep: String] = [
            .kept: "anchor kept", .rendered: "anchor rendered", .verified: "anchor verified",
        ]

        /// The operation whose journal step failed (M1-19).
        package enum StepContext: String, Sendable, CaseIterable {
            case start, undo, stop
        }

        /// Names the journal step that failed by its fixed case name; never error text (M1-19 item 4).
        package static func stepFailed(_ context: StepContext, step: DaemonStep) {
            emit(context.rawValue + " failed at step: " + step.rawValue)
        }

        /// The kind of owned route whose install failed (M1-19 item 4).
        package enum RouteKind: String, Sendable, CaseIterable {
            case canary
            case tunnelIPv4 = "tunnel ipv4"
            case tunnelIPv6 = "tunnel ipv6"
        }

        /// Names the route kind and the kernel's errno only.
        package static func routeFailed(_ kind: RouteKind, code: Int32) {
            emit("route install failed, route: " + kind.rawValue + " code: " + String(code))
        }

        /// Fixed ownership verdict; the Daemon target's engine factory uses it as well.
        public static func ownership(_ event: OwnershipEvent) {
            emit("ownership: " + (ownershipLabels[event] ?? "unknown"))
        }

        /// Every case has a label; the Lab test `ownership labels cover every event` checks it.
        package static let ownershipLabels: [OwnershipEvent: String] = [
            .tunnelIdentityDrift: "tunnel identity drift",
            .tunnelIdentityMissing: "tunnel identity missing",
            .tunnelDescriptorMissing: "tunnel descriptor missing",
            .canaryIdentityDrift: "canary identity drift",
            .routeInterfaceDrift: "route interface drift",
            .deviceInterfaceDrift: "device interface drift",
            .canaryInterfaceMissing: "canary interface missing",
            .foreignRoute: "foreign route",
            .tunnelRouteMissing: "tunnel route missing",
            .canaryRouteMissing: "canary route missing",
            .policyMismatch: "policy mismatch",
            .dnsUnverified: "dns unverified",
            .engineInterfaceMismatch: "engine interface mismatch",
            .engineInterfaceMissing: "engine interface missing",
            .canaryAdopted: "canary adopted",
            .canaryReplaced: "canary replaced",
        ]

        /// Interface snapshot for an ownership refusal: name, recorded and current index, and the fence check that
        /// failed (index, descriptor, link address, address). No address, descriptor, key or profile data (M1-18).
        public static func interface(_ expected: TunnelIdentity, current: TunnelIdentity?, breach: InterfaceFence.Breach) {
            guard let current, breach != .absent else {
                emit("ownership: interface \(expected.name) index \(expected.interfaceIndex)->absent")
                return
            }
            let check = breachLabels[breach] ?? "unknown"
            emit("ownership: interface \(expected.name) index \(expected.interfaceIndex)->\(current.interfaceIndex) check \(check)")
        }

        /// Every fence check has a label; the Lab test `M1-18 fence check labels cover every check` checks it.
        package static let breachLabels: [InterfaceFence.Breach: String] = [
            .absent: "absent", .index: "index", .descriptor: "descriptor", .linkAddress: "link address", .address: "address",
        ]

        private static func emit(_ line: String) {
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "daemon").log("\(line, privacy: .public)")
            publicLineObserver?(line)
        }

        private static func phase(_ phase: TunnelPhase) -> (phase: String, reason: String) {
            switch phase {
            case .idle: ("idle", "none")
            case .preparing: ("preparing", "none")
            case .configuring: ("configuring", "none")
            case .active: ("active", "none")
            case let .reasserting(_, reason): ("reasserting", reason.rawValue)
            case .captiveWindow: ("captivewindow", "none")
            case .stopping: ("stopping", "none")
            case let .failed(error, _, _): ("failed", failureReason(error))
            }
        }

        private static func protection(_ protection: ProtectionState) -> String {
            switch protection {
            case .protected: "protected"
            case .blocked: "blocked"
            case .unprotected, .captiveWindow: "unprotected"
            case .unknown, .unsupported: "unknown"
            }
        }

        /// Exhaustive wire taxonomy; associated values never contribute to the public vocabulary.
        private static func failureReason(_ error: TunnelError) -> String {
            switch error {
            case .profileNotFound: "profileNotFound"
            case .invalidConfiguration: "invalidConfiguration"
            case .engine: "engine"
            case .anotherTunnelActive, .revisionConflict, .busy, .secretsUnavailable, .backendUnavailable,
                 .serviceRecovering, .permissionDenied, .timedOut, .cancelled: simpleFailureReason(error)
            }
        }

        private static func simpleFailureReason(_ error: TunnelError) -> String {
            switch error {
            case .anotherTunnelActive: "anotherTunnelActive"
            case .revisionConflict: "revisionConflict"
            case .busy: "busy"
            case .secretsUnavailable: "secretsUnavailable"
            case .backendUnavailable: "backendUnavailable"
            case .serviceRecovering: "serviceRecovering"
            case .permissionDenied: "permissionDenied"
            case .timedOut: "timedOut"
            case .cancelled: "cancelled"
            default: "none"
            }
        }
    }
#endif
