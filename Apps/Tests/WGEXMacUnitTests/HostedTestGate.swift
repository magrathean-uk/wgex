// SPDX-License-Identifier: MIT
import Foundation
import Security
import WGEXCore
import WGEXDaemonProtocol

public enum HostedTestGate {
    public static var enabled: Bool {
        guard ProcessInfo.processInfo.environment["WGEX_HOSTED_TESTS"] == "1",
              Bundle.main.bundleIdentifier == BuildIdentifiers.current.app,
              HypervisorPresence.isVirtualMachine(SystemSysctl()) else { return false }
        var code: SecCode?
        var requirement: SecRequirement?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(RequirementStrings.current.clientRequirement as CFString, [], &requirement) == errSecSuccess
        else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}
