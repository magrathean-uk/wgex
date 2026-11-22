// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private struct UserStringsTests {
    @Test(arguments: ConfigDiagnostic.Code.allCases)
    func `every diagnostic has catalogue copy and round trips`(code: ConfigDiagnostic.Code) throws {
        let value = ConfigDiagnostic(severity: .warning, code: code, line: 7)
        #expect(!value.message.isEmpty)
        #expect(UserStrings.diagnosticCatalogue[code] == value.message)
        #expect(!value.message.lowercased().contains("always " + "protected"))
        #expect(try JSONDecoder().decode(ConfigDiagnostic.self, from: JSONEncoder().encode(value)) == value)
        let error = ConfigValidationError(diagnostics: [value])
        #expect(try JSONDecoder().decode(ConfigValidationError.self, from: JSONEncoder().encode(error)) == error)
    }

    @Test
    func `state names and notifications make bounded claims`() {
        #expect([
            UserStrings.protected,
            UserStrings.blocked,
            UserStrings.captiveWindow,
            UserStrings.unprotected,
            UserStrings.unsupported,
            UserStrings.unknown,
        ] == [
            "Protected",
            "Blocked",
            "Captive window",
            "Unprotected",
            "Unsupported",
            "Unknown",
        ])
        #expect(UserStrings.secureInstallNeeded == "Secure install needed")
        let notifications = [
            UserStrings.blockedNotificationTitle,
            UserStrings.blockedNotificationBody,
            UserStrings.failedNotificationTitle,
            UserStrings.failedNotificationBody,
            UserStrings.unknownNotificationTitle,
            UserStrings.unknownNotificationBody,
            UserStrings.secureInstallNotificationBody,
            UserStrings.openWGEX,
            UserStrings.disconnect,
        ]
        #expect(notifications.allSatisfy { !$0.isEmpty && !$0.lowercased().contains("always " + "protected") })
        #expect(UserStrings.unknownNotificationBody.contains("may leave"))
        #expect(UserStrings.failedNotificationBody.contains("check whether traffic is blocked"))
    }
}
