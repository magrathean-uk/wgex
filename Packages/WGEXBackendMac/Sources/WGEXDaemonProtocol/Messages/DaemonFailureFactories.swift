// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

public extension DaemonFailure {
    /// Fixed minimum-build refusal.
    static var floorDowngradeDetected: Self {
        Self(code: .floorDowngradeDetected)
    }

    /// Fixed TunnelControllerError staleGeneration category.
    static func controllerStaleGeneration(expected: Generation, actual: Generation) -> Self {
        Self(
            code: .controllerStaleGeneration,
            detail: "\(expected.rawValue):\(actual.rawValue)",
        )
    }

    /// Fixed TunnelControllerError superseded category.
    static func controllerSuperseded(by generation: Generation)
        -> Self
    {
        Self(code: .controllerSuperseded, detail: "\(generation.rawValue)")
    }

    /// Fixed TunnelControllerError anotherTunnelActive category.
    static var controllerAnotherTunnelActive: Self {
        Self(code: .controllerAnotherTunnelActive)
    }

    /// Fixed TunnelControllerError invalidConfiguration category.
    static var controllerInvalidConfiguration: Self {
        Self(code: .controllerInvalidConfiguration)
    }

    /// Fixed TunnelControllerError secretsUnavailable category.
    static var controllerSecretsUnavailable: Self {
        Self(code: .controllerSecretsUnavailable)
    }

    /// Fixed TunnelControllerError operationFailed category.
    static var controllerOperationFailed: Self {
        Self(code: .controllerOperationFailed)
    }

    /// Fixed TunnelControllerError recoveryRequired category.
    static var controllerRecoveryRequired: Self {
        Self(code: .controllerRecoveryRequired)
    }

    /// Fixed TunnelControllerError notActive category.
    static var controllerNotActive: Self {
        Self(code: .controllerNotActive)
    }

    /// Fixed TunnelControllerError policyVerificationFailed category.
    static var controllerPolicyVerificationFailed: Self {
        Self(code: .controllerPolicyVerificationFailed)
    }

    /// Fixed HostAdapterError labRequired category.
    static var hostLabRequired: Self {
        Self(code: .hostLabRequired)
    }

    /// Fixed HostAdapterError noPrimaryInterface category.
    static var hostNoPrimaryInterface: Self {
        Self(code: .hostNoPrimaryInterface)
    }

    /// Fixed HostAdapterError alreadyStarted category.
    static var hostAlreadyStarted: Self {
        Self(code: .hostAlreadyStarted)
    }

    /// Fixed HostAdapterError operationInProgress category.
    static var hostOperationInProgress: Self {
        Self(code: .hostOperationInProgress)
    }

    /// Fixed HostAdapterError unsupportedPlatform category.
    static var hostUnsupportedPlatform: Self {
        Self(code: .hostUnsupportedPlatform)
    }

    /// Fixed HostAdapterError unboundInterfaces category.
    static var hostUnboundInterfaces: Self {
        Self(code: .hostUnboundInterfaces)
    }

    /// Fixed HostAdapterError system category.
    static func hostSystem(_ status: Int32) -> Self {
        Self(kind: .hostSystem, status: status)
    }

    /// Fixed HostAdapterError missingKey category.
    static var hostMissingKey: Self {
        Self(code: .hostMissingKey)
    }

    /// Fixed PacketFilterFailure invalidInput category.
    static func pfInvalidInput(_ detail: String) -> Self {
        Self(code: .pfInvalidInput, detail: detail)
    }

    /// Fixed PacketFilterFailure unavailable category.
    static var pfUnavailable: Self {
        Self(code: .pfUnavailable)
    }

    /// Fixed PacketFilterFailure deadline category.
    static var pfDeadline: Self {
        Self(code: .pfDeadline)
    }

    /// Fixed PacketFilterFailure process category.
    static func pfProcess(_ status: Int32) -> Self {
        Self(kind: .pfProcess, status: status)
    }

    /// Fixed PacketFilterFailure verification category.
    static var pfVerification: Self {
        Self(code: .pfVerification)
    }

    /// Fixed PacketFilterFailure token category.
    static var pfToken: Self {
        Self(code: .pfToken)
    }

    /// Fixed PacketFilterFailure journal category.
    static var pfJournal: Self {
        Self(code: .pfJournal)
    }

    /// Fixed StateDirectoryError unsafePath category.
    static var stateUnsafePath: Self {
        Self(code: .stateUnsafePath)
    }

    /// Fixed StateDirectoryError unsafeMetadata category.
    static var stateUnsafeMetadata: Self {
        Self(code: .stateUnsafeMetadata)
    }

    /// Fixed StateDirectoryError tooLarge category.
    static var stateTooLarge: Self {
        Self(code: .stateTooLarge)
    }

    /// Fixed StateDirectoryError system category.
    static func stateSystem(_ status: Int32) -> Self {
        Self(kind: .stateSystem, status: status)
    }

    /// Fixed StateDirectoryError invalidDocument category.
    static var stateInvalidDocument: Self {
        Self(code: .stateInvalidDocument)
    }

    /// Fixed StateDirectoryError rollbackFailed category.
    static func stateRollbackFailed(_ status: Int32) -> Self {
        Self(kind: .stateRollbackFailed, status: status)
    }

    /// Fixed ProfileRegistryError notFound category.
    static var registryNotFound: Self {
        Self(code: .registryNotFound)
    }

    /// Fixed ProfileRegistryError notOwner category.
    static var registryNotOwner: Self {
        Self(code: .registryNotOwner)
    }

    /// Fixed ProfileRegistryError invalidProfile category.
    static var registryInvalidProfile: Self {
        Self(code: .registryInvalidProfile)
    }

    /// Fixed ProfileRegistryError invalidSecretReference category.
    static var registryInvalidSecretReference: Self {
        Self(code: .registryInvalidSecretReference)
    }

    /// Fixed ProfileRegistryError revisionConflict category.
    static var registryRevisionConflict: Self {
        Self(code: .registryRevisionConflict)
    }

    /// Fixed ProfileRegistryError busy category.
    static var registryBusy: Self {
        Self(code: .registryBusy)
    }

    /// Fixed ProfileRegistryError multipleBootProfiles category.
    static var registryMultipleBootProfiles: Self {
        Self(code: .registryMultipleBootProfiles)
    }

    /// Fixed DaemonJournalError staleGeneration category.
    static var journalStaleGeneration: Self {
        Self(code: .journalStaleGeneration)
    }

    /// Fixed DaemonJournalError exhausted category.
    static var journalExhausted: Self {
        Self(code: .journalExhausted)
    }

    /// Fixed DaemonJournalError invalidVersion category.
    static var journalInvalidVersion: Self {
        Self(code: .journalInvalidVersion)
    }

    /// Fixed RouteCodecError malformed category.
    static var routeMalformed: Self {
        Self(code: .routeMalformed)
    }

    /// Fixed RouteCodecError unsupported category.
    static var routeUnsupported: Self {
        Self(code: .routeUnsupported)
    }

    /// Fixed RouteCodecError invalidRoute category.
    static var routeInvalidRoute: Self {
        Self(code: .routeInvalidRoute)
    }

    /// Fixed RouteCodecError exhausted category.
    static var routeExhausted: Self {
        Self(code: .routeExhausted)
    }

    /// Fixed CaptiveWindowError closed category.
    static var captiveClosed: Self {
        Self(code: .captiveClosed)
    }

    /// Fixed CaptiveWindowError alreadyExtended category.
    static var captiveAlreadyExtended: Self {
        Self(code: .captiveAlreadyExtended)
    }

    /// Fixed CaptiveWindowError invalidDuration category.
    static var captiveInvalidDuration: Self {
        Self(code: .captiveInvalidDuration)
    }

    /// Fixed CaptiveWindowError expired category.
    static var captiveExpired: Self {
        Self(code: .captiveExpired)
    }

    /// Fixed WrappingKeyProvisionError accessRepairFailed category.
    static var keyAccessRepairFailed: Self {
        Self(code: .keyAccessRepairFailed)
    }

    /// Fixed DaemonIntegrationError notImplemented category.
    static func integrationNotImplemented(_ detail: String) -> Self {
        Self(code: .integrationNotImplemented, detail: detail)
    }
}

public extension DaemonFailure {
    /// Converts only the immutable, payload-free Core seam at the compatibility boundary.
    static func adaptingPort(_ error: DaemonPortError) -> Self {
        switch error {
        case let .system(code): .portSystem(code: code)
        case .notOwned: .portNotOwned
        case .timedOut: .portTimedOut
        case .noAnswer: .portNoAnswer
        }
    }

    /// Numeric system result from a daemon port.
    static func portSystem(code: Int32) -> Self {
        Self(kind: .portSystem, status: code)
    }

    /// The observed resource is not owned by this generation.
    static var portNotOwned: Self {
        Self(code: .portNotOwned)
    }

    /// The bounded port operation reached its deadline.
    static var portTimedOut: Self {
        Self(code: .portTimedOut)
    }

    /// No valid endpoint address was returned by the bound resolver.
    static var portNoAnswer: Self {
        Self(code: .portNoAnswer)
    }

    /// Identifies compatibility port failures without treating unrelated canonical errors as port errors.
    var isPortFailure: Bool {
        (900 ... 903).contains(code)
    }
}
