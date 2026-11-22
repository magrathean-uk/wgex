// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonProtocol

private struct DaemonFailureTests {
    @Test
    func `private details do not change failure equality or catch patterns`() {
        let first = DaemonFailure.pfInvalidInput("first private context")
        let second = DaemonFailure.pfInvalidInput("different private context")
        #expect(first == second)
        let erased: any Error = second
        #expect(first ~= erased)
        #expect(DaemonFailure.portSystem(code: 5) != .portSystem(code: 6))
    }

    @Test
    func `signing and bundle validation failures use fixed withheld categories`() throws {
        #expect(DaemonFailure.Code.securitySigningInformation.rawValue == 950)
        #expect(DaemonFailure.Code.securityInvalidBundleLayout.rawValue == 952)
        #expect(DaemonFailure.Code.securityLabInvalidIdentifier.rawValue == 956)
        let row = try #require(DaemonFailure.catalog[.securitySigningInformation])
        #expect(row.diagnosticType == "UnknownError")
        #expect(row.diagnosticLabel == "withheld")
        #expect(DaemonFailure(code: .securityInvalidBundleLayout).wireError() == .tunnel(.backendUnavailable))
    }

    @Test
    func `legacy Core port errors are classified at the compatibility boundary`() {
        #expect(DaemonFailure.adaptingPort(.notOwned).kind == .portNotOwned)
        #expect(DaemonFailure.adaptingPort(.noAnswer).kind == .portNoAnswer)
        #expect(DaemonFailure.adaptingPort(.timedOut).kind == .portTimedOut)
        let failure = DaemonFailure.adaptingPort(.system(code: 5))
        #expect(failure.code == 900)
        #expect(failure.systemStatus == 5)
        #expect(failure.wireError() == .tunnel(.backendUnavailable))
    }

    @Test(arguments: DaemonFailure.Code.allCases)
    func `every stable failure code has an explicit wire and CLI row`(_ code: DaemonFailure.Code) throws {
        let row = try #require(DaemonFailure.catalog[code])
        let failure = DaemonFailure(code: code, detail: "withheld-detail")
        #expect(failure.code == code.rawValue)
        #expect(!String(describing: failure).contains("withheld-detail"))
        #expect(!String(reflecting: failure).contains("withheld-detail"))
        #expect(row.cliExitCode > 0)
        let wire = failure.wireError()
        #expect(try !String(decoding: WireCodec.encode(wire), as: UTF8.self).contains("withheld-detail"))
    }

    @Test
    func `resolver refusal round trips through the existing envelope without accepting arbitrary reasons`() throws {
        let wire = DaemonFailure.startup(.resolverUnavailable).wireError()
        let decoded = try WireCodec.decode(DaemonError.self, from: WireCodec.encode(wire))
        #expect(DaemonFailure(wire: decoded).kind == .startupResolverUnavailable)
        #expect(decoded.presentation.cliName == "underlayResolverNoAnswer")
        #expect(DaemonFailure(wire: .protectionUnknown(reason: "untrusted private text")).kind == .protectionUnknown)
    }

    @Test
    func `wire taxonomy and established CLI exits remain fixed`() {
        #expect(DaemonError.protectionUnknown(reason: "fixed").presentation.cliExitCode == 12)
        #expect(DaemonError.busy.presentation.cliExitCode == 13)
        #expect(DaemonError.tunnel(.revisionConflict).presentation.cliExitCode == 18)
        #expect(DaemonError.tunnel(.timedOut).presentation.cliExitCode == 8)
        #expect(DaemonError.busy.presentation.tunnelError == .busy)
        #expect(DaemonError.recovering.presentation.tunnelError == .serviceRecovering)
        #expect(Set(DaemonFailure.Code.allCases.map(\.rawValue)).count == DaemonFailure.Code.allCases.count)
    }
}

private struct DaemonFailureGoldenTests {
    private struct Row: Sendable {
        let kind: DaemonFailure.Code
        let code: Int
        let wire: DaemonError?
        let shell: TunnelError
        let name: String
        let exit: Int32
        let type: String
        let label: String
        init(
            _ kind: DaemonFailure.Code,
            _ code: Int,
            _ wire: DaemonError?,
            _ shell: TunnelError,
            _ name: String,
            _ exit: Int32,
            _ type: String,
            _ label: String,
        ) {
            self.kind = kind; self.code = code; self.wire = wire; self.shell = shell
            self.name = name; self.exit = exit; self.type = type; self.label = label
        }
    }

    @Test(arguments: rows)
    private func `literal public failure catalogue cannot drift`(_ expected: Row) throws {
        let actual = try #require(DaemonFailure.catalog[expected.kind])
        #expect(expected.kind.rawValue == expected.code)
        #expect(normalise(actual.wireError) == expected.wire)
        #expect(normalise(actual.tunnelError) == expected.shell)
        #expect(actual.cliName == expected.name)
        #expect(actual.cliExitCode == expected.exit)
        #expect(actual.diagnosticType == expected.type)
        #expect(actual.diagnosticLabel == expected.label)
        let wire = DaemonFailure(code: expected.kind).wireError(profileID: Self.profileID)
        #expect(normalise(wire) == (expected.wire ?? .tunnel(.backendUnavailable)))
    }

    @Test
    func `golden rows cover every public code exactly once`() {
        #expect(Set(Self.rows.map(\.kind)) == Set(DaemonFailure.Code.allCases))
        #expect(Set(Self.rows.map(\.code)).count == Self.rows.count)
    }

    private func normalise(_ error: DaemonError?) -> DaemonError? {
        switch error {
        case .some(.profileNotFound): .profileNotFound(Self.profileID)
        case let .some(.tunnel(error)): .tunnel(normalise(error))
        default: error
        }
    }

    private func normalise(_ error: TunnelError) -> TunnelError {
        if case .profileNotFound = error {
            return .profileNotFound(Self.profileID)
        }
        return error
    }
}

private extension DaemonFailureGoldenTests {
    static let profileID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    private static let rows: [Row] = [
        .init(
            .pfCanaryFailed,
            307,
            .protectionUnknown(reason: "canaryFailed"),
            .backendUnavailable,
            "canaryFailed",
            12,
            "UnknownError",
            "withheld",
        ),
        .init(
            .captiveUnavailable,
            754,
            .protectionUnknown(reason: "captiveUnavailable"),
            .backendUnavailable,
            "captiveUnavailable",
            12,
            "DaemonPortError",
            "system",
        ),
        .init(
            .captiveDNSFailed,
            755,
            .protectionUnknown(reason: "captiveDNSFailed"),
            .backendUnavailable,
            "captiveDNSFailed",
            12,
            "DaemonPortError",
            "system",
        ),
        .init(
            .captiveRoutesFailed,
            756,
            .protectionUnknown(reason: "captiveRoutesFailed"),
            .backendUnavailable,
            "captiveRoutesFailed",
            12,
            "DaemonPortError",
            "system",
        ),
        .init(
            .captivePolicyFailed,
            757,
            .protectionUnknown(reason: "captivePolicyFailed"),
            .backendUnavailable,
            "captivePolicyFailed",
            12,
            "DaemonPortError",
            "system",
        ),
        .init(.malformedMessage, 1, .malformedMessage, .backendUnavailable, "protocol", 17, "UnknownError", "withheld"),
        .init(.messageTooLarge, 2, .messageTooLarge(0), .backendUnavailable, "protocol", 17, "UnknownError", "withheld"),
        .init(
            .unsupportedProtocolVersion,
            3,
            .unsupportedProtocolVersion(0),
            .backendUnavailable,
            "protocol",
            17,
            "UnknownError",
            "withheld",
        ),
        .init(.notAuthorised, 4, .notAuthorised(.notOwner), .permissionDenied, "unauthorised", 4, "UnknownError", "withheld"),
        .init(
            .profileNotFound,
            5,
            .profileNotFound(Self.profileID),
            .profileNotFound(Self.profileID),
            "profileNotFound",
            11,
            "UnknownError",
            "withheld",
        ),
        .init(.secretsUnavailable, 6, .secretsUnavailable, .secretsUnavailable, "secretsUnavailable", 3, "UnknownError", "withheld"),
        .init(.downgradeDetected, 7, .downgradeDetected, .backendUnavailable, "downgradeDetected", 4, "UnknownError", "withheld"),
        .init(.secureInstallRequired, 8, .secureInstallRequired, .permissionDenied, "secureInstallRequired", 4, "UnknownError", "withheld"),
        .init(
            .protectionUnknown,
            9,
            .protectionUnknown(reason: "protectionUnknown"),
            .backendUnavailable,
            "protectionUnknown",
            12,
            "UnknownError",
            "withheld",
        ),
        .init(.recovering, 10, .recovering, .serviceRecovering, "recovering", 5, "UnknownError", "withheld"),
        .init(
            .multipleBootProfiles,
            11,
            .multipleBootProfiles,
            .invalidConfiguration(.multipleBootProfiles),
            "multipleBootProfiles",
            7,
            "UnknownError",
            "withheld",
        ),
        .init(.slotRefused, 12, .busy, .busy, "busy", 13, "UnknownError", "withheld"),
        .init(.rateLimited, 13, .rateLimited, .backendUnavailable, "rateLimited", 15, "UnknownError", "withheld"),
        .init(.unauthorised, 14, .unauthorised, .permissionDenied, "unauthorised", 4, "UnknownError", "withheld"),
        .init(.handshakeRequired, 15, .handshakeRequired, .backendUnavailable, "protocol", 17, "UnknownError", "withheld"),
        .init(.staleGeneration, 16, .staleGeneration, .backendUnavailable, "staleGeneration", 14, "UnknownError", "withheld"),
        .init(.anotherTunnelActive, 17, .anotherTunnelActive, .anotherTunnelActive, "anotherTunnelActive", 6, "UnknownError", "withheld"),
        .init(.disconnected, 18, .disconnected, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.subscriptionLimit, 19, .subscriptionLimit, .backendUnavailable, "rateLimited", 15, "UnknownError", "withheld"),
        .init(
            .tunnelAnotherActive,
            30,
            .tunnel(.anotherTunnelActive),
            .anotherTunnelActive,
            "anotherTunnelActive",
            6,
            "UnknownError",
            "withheld",
        ),
        .init(
            .tunnelProfileMissing,
            31,
            .tunnel(.profileNotFound(Self.profileID)),
            .profileNotFound(Self.profileID),
            "profileNotFound",
            11,
            "UnknownError",
            "withheld",
        ),
        .init(
            .tunnelInvalidConfiguration,
            32,
            .tunnel(.invalidConfiguration(.invalidProfile)),
            .invalidConfiguration(.invalidProfile),
            "invalidConfiguration",
            7,
            "UnknownError",
            "withheld",
        ),
        .init(
            .tunnelRevisionConflict,
            33,
            .tunnel(.revisionConflict),
            .revisionConflict,
            "revisionConflict",
            18,
            "UnknownError",
            "withheld",
        ),
        .init(.tunnelBusy, 34, .tunnel(.busy), .busy, "busy", 13, "UnknownError", "withheld"),
        .init(
            .tunnelSecretsUnavailable,
            35,
            .tunnel(.secretsUnavailable),
            .secretsUnavailable,
            "secretsUnavailable",
            3,
            "UnknownError",
            "withheld",
        ),
        .init(
            .tunnelBackendUnavailable,
            36,
            .tunnel(.backendUnavailable),
            .backendUnavailable,
            "daemonUnavailable",
            1,
            "UnknownError",
            "withheld",
        ),
        .init(.tunnelRecovering, 37, .tunnel(.serviceRecovering), .serviceRecovering, "recovering", 5, "UnknownError", "withheld"),
        .init(.tunnelPermissionDenied, 38, .tunnel(.permissionDenied), .permissionDenied, "unauthorised", 4, "UnknownError", "withheld"),
        .init(.tunnelTimedOut, 39, .tunnel(.timedOut), .timedOut, "timedOut", 8, "UnknownError", "withheld"),
        .init(.tunnelEngine, 40, .tunnel(.engine(code: -99)), .engine(code: -99), "engine", 9, "UnknownError", "withheld"),
        .init(.tunnelCancelled, 41, .tunnel(.cancelled), .cancelled, "cancelled", 10, "UnknownError", "withheld"),
        .init(.controllerStaleGeneration, 100, .staleGeneration, .backendUnavailable, "staleGeneration", 14, "UnknownError", "withheld"),
        .init(.controllerSuperseded, 101, .tunnel(.cancelled), .cancelled, "cancelled", 10, "UnknownError", "withheld"),
        .init(
            .controllerAnotherTunnelActive,
            102,
            .anotherTunnelActive,
            .anotherTunnelActive,
            "anotherTunnelActive",
            6,
            "UnknownError",
            "withheld",
        ),
        .init(
            .controllerInvalidConfiguration,
            103,
            .tunnel(.invalidConfiguration(.invalidProfile)),
            .invalidConfiguration(.invalidProfile),
            "invalidConfiguration",
            7,
            "UnknownError",
            "withheld",
        ),
        .init(
            .controllerSecretsUnavailable,
            104,
            .secretsUnavailable,
            .secretsUnavailable,
            "secretsUnavailable",
            3,
            "UnknownError",
            "withheld",
        ),
        .init(.controllerOperationFailed, 105, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.controllerRecoveryRequired, 106, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.controllerNotActive, 107, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.controllerPolicyVerificationFailed, 108, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.hostLabRequired, 200, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "labRequired"),
        .init(.hostNoPrimaryInterface, 201, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "noPrimaryInterface"),
        .init(.hostAlreadyStarted, 202, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "alreadyStarted"),
        .init(.hostOperationInProgress, 203, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "operationInProgress"),
        .init(.hostUnsupportedPlatform, 204, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "unsupportedPlatform"),
        .init(.hostUnboundInterfaces, 205, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "unboundInterfaces"),
        .init(.hostSystem, 206, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "system"),
        .init(.hostMissingKey, 207, nil, .backendUnavailable, "daemonUnavailable", 1, "HostAdapterError", "missingKey"),
        .init(.pfInvalidInput, 300, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "invalidInput"),
        .init(.pfUnavailable, 301, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "unavailable"),
        .init(.pfDeadline, 302, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "deadline"),
        .init(.pfProcess, 303, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "process"),
        .init(.pfVerification, 304, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "verification"),
        .init(.pfToken, 305, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "token"),
        .init(.pfJournal, 306, nil, .backendUnavailable, "daemonUnavailable", 1, "PacketFilterFailure", "journal"),
        .init(.stateUnsafePath, 400, nil, .backendUnavailable, "daemonUnavailable", 1, "StateDirectoryError", "unsafePath"),
        .init(.stateUnsafeMetadata, 401, nil, .backendUnavailable, "daemonUnavailable", 1, "StateDirectoryError", "unsafeMetadata"),
        .init(.stateTooLarge, 402, nil, .backendUnavailable, "daemonUnavailable", 1, "StateDirectoryError", "tooLarge"),
        .init(.stateSystem, 403, nil, .backendUnavailable, "daemonUnavailable", 1, "StateDirectoryError", "system"),
        .init(.stateInvalidDocument, 404, nil, .backendUnavailable, "daemonUnavailable", 1, "StateDirectoryError", "invalidDocument"),
        .init(.stateRollbackFailed, 405, nil, .backendUnavailable, "daemonUnavailable", 1, "StateDirectoryError", "rollbackFailed"),
        .init(.floorDowngradeDetected, 450, nil, .backendUnavailable, "daemonUnavailable", 1, "FloorError", "downgradeDetected"),
        .init(
            .registryNotFound,
            500,
            .profileNotFound(Self.profileID),
            .profileNotFound(Self.profileID),
            "profileNotFound",
            11,
            "UnknownError",
            "withheld",
        ),
        .init(.registryNotOwner, 501, .notAuthorised(.notOwner), .permissionDenied, "unauthorised", 4, "UnknownError", "withheld"),
        .init(
            .registryInvalidProfile,
            502,
            .tunnel(.invalidConfiguration(.invalidProfile)),
            .invalidConfiguration(.invalidProfile),
            "invalidConfiguration",
            7,
            "UnknownError",
            "withheld",
        ),
        .init(
            .registryInvalidSecretReference,
            503,
            .tunnel(.invalidConfiguration(.invalidProfile)),
            .invalidConfiguration(.invalidProfile),
            "invalidConfiguration",
            7,
            "UnknownError",
            "withheld",
        ),
        .init(
            .registryRevisionConflict,
            504,
            .tunnel(.revisionConflict),
            .revisionConflict,
            "revisionConflict",
            18,
            "UnknownError",
            "withheld",
        ),
        .init(.registryBusy, 505, .busy, .busy, "busy", 13, "UnknownError", "withheld"),
        .init(
            .registryMultipleBootProfiles,
            506,
            .multipleBootProfiles,
            .invalidConfiguration(.multipleBootProfiles),
            "multipleBootProfiles",
            7,
            "UnknownError",
            "withheld",
        ),
        .init(.journalStaleGeneration, 550, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonJournalError", "staleGeneration"),
        .init(.journalExhausted, 551, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonJournalError", "exhausted"),
        .init(.journalInvalidVersion, 552, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonJournalError", "invalidVersion"),
        .init(.routeMalformed, 700, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.routeUnsupported, 701, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.routeInvalidRoute, 702, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.routeExhausted, 703, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.captiveClosed, 750, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.captiveAlreadyExtended, 751, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.captiveInvalidDuration, 752, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.captiveExpired, 753, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.keyAccessRepairFailed, 800, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.integrationNotImplemented, 850, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(
            .onDemandNotConfigured, 860, .onDemandNotConfigured, .invalidConfiguration(.invalidProfile),
            "onDemandNotConfigured", 7, "UnknownError", "withheld",
        ),
        .init(
            .uninstallFailed, 870, .uninstallFailed(step: .admission), .backendUnavailable,
            "uninstallFailed", 19, "UnknownError", "withheld",
        ),
        .init(.startupNoPrimaryInterface, 601, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.startupProfileUnavailable, 602, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.startupMultipleBootProfiles, 603, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(
            .startupResolverUnavailable, 604, .protectionUnknown(reason: "underlayResolverNoAnswer"),
            .backendUnavailable, "underlayResolverNoAnswer", 8, "UnknownError", "withheld",
        ),
        .init(.startupMonitorStartFailed, 605, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.startupReconciliationFailed, 606, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.startupIntentStartFailed, 607, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.startupBlockingPolicyFailed, 608, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.startupSecureInstallRequired, 609, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.portSystem, 900, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonPortError", "system"),
        .init(.portNotOwned, 901, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonPortError", "notOwned"),
        .init(.portTimedOut, 902, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonPortError", "timedOut"),
        .init(.portNoAnswer, 903, nil, .backendUnavailable, "daemonUnavailable", 1, "DaemonPortError", "noAnswer"),
        .init(.securitySigningInformation, 950, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.securityMissingHash, 951, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.securityInvalidBundleLayout, 952, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.securityInvalidExecutable, 953, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.securityLabMissingHash, 954, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.securityLabInvalidHash, 955, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(.securityLabInvalidIdentifier, 956, nil, .backendUnavailable, "daemonUnavailable", 1, "UnknownError", "withheld"),
        .init(
            .secretsHandoffDisconnected,
            957,
            .protectionUnknown(reason: "secretsHandoffDisconnected"),
            .secretsUnavailable,
            "secretsHandoffDisconnected",
            3,
            "UnknownError",
            "withheld",
        ),
    ]
}
