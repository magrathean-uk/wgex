// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXDaemonProtocol

private struct AdminRightShapeTests {
    enum Weakening: String, CaseIterable, Sendable {
        case allowClass, denyClass, allowRule, denyRule, ownerRule, mixedAllow, mixedDeny, mixedOwner
        case allowKey, denyKey, staffGroup, noGroup, noAuthentication, emptyRule, entitled, sessionOwner, threshold, malformedUserRule
        case adminUserClass, zeroTimeoutDelegate, sharedDelegate, cacheShared, cacheTimeout
        var dictionary: [String: Any] {
            let delegate = AdminRightDefinition.delegateName
            var value: [String: Any] = ["class": "rule", "rule": [delegate]]
            switch self {
            case .allowClass: value["class"] = "allow"
            case .denyClass: value["class"] = "deny"
            case .allowRule: value["rule"] = "allow"
            case .denyRule: value["rule"] = "deny"
            case .ownerRule: value["rule"] = "authenticate-session-owner"
            case .mixedAllow: value["rule"] = [delegate, "allow"]
            case .mixedDeny: value["rule"] = [delegate, "deny"]
            case .mixedOwner: value["rule"] = [delegate, "authenticate-session-owner"]
            case .allowKey: value["allow"] = true
            case .denyKey: value["deny"] = true
            case .staffGroup: value = ["class": "user", "group": "staff"]
            case .noGroup: value = ["class": "user"]
            case .noAuthentication: value = ["class": "user", "group": "admin", "authenticate-user": false]
            case .emptyRule: value["rule"] = [] as [String]
            case .entitled: value["entitled"] = true
            case .sessionOwner: value["session-owner"] = true
            case .threshold: value["k-of-n"] = 0
            case .malformedUserRule: value = ["class": "user", "group": "admin", "rule": [1]]
            case .adminUserClass: value = ["class": "user", "group": "admin", "shared": true, "timeout": 300]
            case .zeroTimeoutDelegate: value["rule"] = ["authenticate-admin"]
            case .sharedDelegate: value["rule"] = ["authenticate-admin-30"]
            case .cacheShared: value["shared"] = false
            case .cacheTimeout: value["timeout"] = 30
            }
            return value
        }
    }

    @Test(arguments: Weakening.allCases)
    func `every known weakening shape is refused`(_ shape: Weakening) throws {
        let definition = try AdminRightDefinition(dictionary: shape.dictionary)
        #expect(!AdminRightPolicy(read: { definition }, write: {}).isValid())
    }

    @Test(arguments: [false, true])
    func `a rule class read back without cache fields is accepted`(stringRule: Bool) throws {
        let delegate = AdminRightDefinition.delegateName
        let dictionary: [String: Any] = ["class": "rule", "rule": stringRule ? delegate as Any : [delegate] as Any]
        let definition = try AdminRightDefinition(dictionary: dictionary)
        #expect(definition == .required)
        #expect(definition.shared == nil && definition.timeout == nil)
        #expect(AdminRightPolicy(read: { definition }, write: {}).isValid())
    }

    @Test
    func `missing or malformed external forms never read authdb`() {
        let reads = Mutex(0)
        let policy = AdminRightPolicy(read: { reads.withLock { $0 += 1 }; return .required }, write: {})
        #expect(!policy.validateExternalForm(nil, byteCount: 32, verify: { _ in true }))
        #expect(!policy.validateExternalForm(Data([0]), byteCount: 32, verify: { _ in true }))
        #expect(reads.withLock { $0 } == 0)
    }
}
