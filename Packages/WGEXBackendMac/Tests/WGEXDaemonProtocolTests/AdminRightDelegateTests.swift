// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXDaemonProtocol

private struct AdminRightDelegateTests {
    /// authd's read-back of Apple's `authenticate-admin-nonshared` (macOS 26.6.2 shape).
    private static var nonshared: [String: Any] {
        [
            "allow-root": false, "authenticate-user": true, "class": "user", "comment": "Authenticate as an administrator.",
            "created": 812_372_687.5, "group": "admin", "modified": 812_372_687.5, "session-owner": false, "shared": false,
            "timeout": 30, "tries": 10000, "version": 1,
        ]
    }

    enum Weakening: String, CaseIterable, Sendable {
        case allowClass, ruleClass, staffGroup, noGroup, shared, sharedAsInteger, zeroTimeout, longTimeout, noTimeout
        case stringTimeout, booleanTimeout, noAuthentication, allowRoot, sessionOwner, mechanisms, entitled, unknownKey

        var dictionary: [String: Any] {
            var value = AdminRightDelegateTests.nonshared
            switch self {
            case .allowClass: value = ["class": "allow"]
            case .ruleClass: value["class"] = "rule"; value["rule"] = ["authenticate-admin"]
            case .staffGroup: value["group"] = "staff"
            case .noGroup: value["group"] = nil
            case .shared: value["shared"] = true
            case .sharedAsInteger: value["shared"] = 0
            case .zeroTimeout: value["timeout"] = 0
            case .longTimeout: value["timeout"] = 300
            case .noTimeout: value["timeout"] = nil
            case .stringTimeout: value["timeout"] = "30"
            case .booleanTimeout: value["timeout"] = true
            case .noAuthentication: value["authenticate-user"] = false
            case .allowRoot: value["allow-root"] = true
            case .sessionOwner: value["session-owner"] = true
            case .mechanisms: value["mechanisms"] = ["builtin:authenticate"]
            case .entitled: value["entitled"] = false
            case .unknownKey: value["future-bypass"] = false
            }
            return value
        }
    }

    @Test func `the unshared thirty second admin delegate is accepted`() {
        #expect(AdminRightDefinition.delegateName == "authenticate-admin-nonshared")
        #expect(AdminRightDefinition.acceptsDelegate(Self.nonshared))
        var shorter = Self.nonshared
        shorter["timeout"] = 5; shorter["shared"] = nil
        #expect(AdminRightDefinition.acceptsDelegate(shorter))
    }

    @Test(arguments: Weakening.allCases)
    func `a weaker or different delegate is refused`(_ shape: Weakening) {
        #expect(!AdminRightDefinition.acceptsDelegate(shape.dictionary))
    }
}
