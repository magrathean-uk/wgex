// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    import Testing
    @testable import WGEXDaemonCore
    import WGEXDaemonProtocol
    import WGEXEngineInterface
    import WGEXProfileStore

    private struct LabDiagnosticsTests {
        @Test
        func `implementation failures outside the legacy log allowlist retain withheld fields`() {
            let failures = [
                DaemonFailure.controllerNotActive, .registryBusy, .routeMalformed, .captiveExpired,
                .keyAccessRepairFailed, .integrationNotImplemented("withheld-detail"),
            ]
            for failure in failures {
                let fields = DaemonDiagnostics.fields(for: failure)
                #expect(fields.type == "UnknownError")
                #expect(fields.label == "withheld")
                #expect(fields.code == -1)
            }
        }

        private struct UnlistedError: Error, CustomStringConvertible {
            var description: String {
                "arbitrary-private-description"
            }
        }

        @Test
        func `unlisted errors contribute no reflected data`() {
            let fields = DaemonDiagnostics.fields(for: UnlistedError())
            #expect(fields.type == "UnknownError")
            #expect(fields.label == "withheld")
            #expect(fields.code == -1)
        }

        @Test
        func `allowlisted system errors retain only a fixed name case and integer`() {
            let fields = DaemonDiagnostics.fields(for: DaemonFailure.hostSystem(5))
            #expect(fields.type == "HostAdapterError")
            #expect(fields.label == "system")
            #expect(fields.code == 5)
            let invalid = DaemonDiagnostics.fields(for: DaemonFailure.pfInvalidInput("arbitrary-private-description"))
            #expect(invalid.label == "invalidInput")
            #expect(invalid.code == -1)
        }

        private struct Expected: Sendable {
            let error: any Error
            let type: String
            let label: String
            let code: Int32
        }

        private static let cases: [Expected] = [
            Expected(error: DaemonFailure.stateUnsafePath, type: "StateDirectoryError", label: "unsafePath", code: -1),
            Expected(error: DaemonFailure.stateUnsafeMetadata, type: "StateDirectoryError", label: "unsafeMetadata", code: -1),
            Expected(error: DaemonFailure.stateTooLarge, type: "StateDirectoryError", label: "tooLarge", code: -1),
            Expected(error: DaemonFailure.stateSystem(5), type: "StateDirectoryError", label: "system", code: 5),
            Expected(error: DaemonFailure.stateInvalidDocument, type: "StateDirectoryError", label: "invalidDocument", code: -1),
            Expected(error: DaemonFailure.floorDowngradeDetected, type: "FloorError", label: "downgradeDetected", code: -1),
            Expected(error: EngineError.invalidArgument, type: "EngineError", label: "invalidArgument", code: -1),
            Expected(error: EngineError.outOfMemory, type: "EngineError", label: "outOfMemory", code: -2),
            Expected(error: EngineError.invalidHandle, type: "EngineError", label: "invalidHandle", code: -3),
            Expected(error: EngineError.tun, type: "EngineError", label: "tun", code: -4),
            Expected(error: EngineError.bind, type: "EngineError", label: "bind", code: -5),
            Expected(error: EngineError.config, type: "EngineError", label: "config", code: -6),
            Expected(error: EngineError.up, type: "EngineError", label: "up", code: -7),
            Expected(error: EngineError.state, type: "EngineError", label: "state", code: -8),
            Expected(error: EngineError.deviceClosed, type: "EngineError", label: "deviceClosed", code: -9),
            Expected(error: EngineError.internal, type: "EngineError", label: "internal", code: -99),
            Expected(error: EngineError.unknown(code: -123), type: "EngineError", label: "unknown", code: -123),
            Expected(error: SecretStoreError.locked, type: "SecretStoreError", label: "locked", code: -1),
            Expected(error: SecretStoreError.notFound, type: "SecretStoreError", label: "notFound", code: -1),
            Expected(error: SecretStoreError.duplicate, type: "SecretStoreError", label: "duplicate", code: -1),
            Expected(error: SecretStoreError.system(6), type: "SecretStoreError", label: "system", code: 6),
            Expected(error: SecretStoreError.unavailable, type: "SecretStoreError", label: "unavailable", code: -1),
            Expected(error: DaemonFailure.journalStaleGeneration, type: "DaemonJournalError", label: "staleGeneration", code: -1),
            Expected(error: DaemonFailure.journalExhausted, type: "DaemonJournalError", label: "exhausted", code: -1),
            Expected(error: DaemonFailure.journalInvalidVersion, type: "DaemonJournalError", label: "invalidVersion", code: -1),
            Expected(error: DaemonFailure.hostNoPrimaryInterface, type: "HostAdapterError", label: "noPrimaryInterface", code: -1),
            Expected(error: DaemonFailure.hostAlreadyStarted, type: "HostAdapterError", label: "alreadyStarted", code: -1),
            Expected(error: DaemonFailure.hostOperationInProgress, type: "HostAdapterError", label: "operationInProgress", code: -1),
            Expected(error: DaemonFailure.hostUnsupportedPlatform, type: "HostAdapterError", label: "unsupportedPlatform", code: -1),
            Expected(error: DaemonFailure.hostUnboundInterfaces, type: "HostAdapterError", label: "unboundInterfaces", code: -1),
        ]

        @Test(arguments: cases)
        private func `startup and engine error families expose only explicit fields`(expected: Expected) {
            let fields = DaemonDiagnostics.fields(for: expected.error)
            #expect(fields.type == expected.type)
            #expect(fields.label == expected.label)
            #expect(fields.code == expected.code)
        }
    }
#endif
