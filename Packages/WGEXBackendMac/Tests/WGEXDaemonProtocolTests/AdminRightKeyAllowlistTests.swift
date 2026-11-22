// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXDaemonProtocol

private struct AdminRightKeyAllowlistTests {
    @Test(arguments: ["allow", "deny", "entitled", "entitled-group", "future-bypass", "mechanisms"])
    func `unrecognised keys are rejected even with false values`(_ key: String) throws {
        let value = try AdminRightDefinition(dictionary: ["class": "rule", "rule": AdminRightDefinition.delegateName, key: false])
        #expect(!AdminRightPolicy(read: { value }, write: {}).isValid())
    }

    @Test func `rule class metadata and a threshold of one are accepted`() throws {
        let value = try AdminRightDefinition(dictionary: [
            "class": "rule", "rule": AdminRightDefinition.delegateName, "comment": "WGEX", "version": 0,
            "created": 814_991_105.5, "modified": 815_724_327.9, "k-of-n": 1,
            "identifier": "com.magrathean.WGEXApp", "requirement": "identifier com.magrathean.WGEXApp",
        ])
        #expect(AdminRightPolicy(read: { value }, write: {}).isValid())
    }

    @Test(arguments: ["shared", "timeout", "group", "allow-root", "authenticate-user", "session-owner", "tries"])
    func `user class keys never belong to a rule class read back`(_ key: String) throws {
        let value = try AdminRightDefinition(dictionary: ["class": "rule", "rule": AdminRightDefinition.delegateName, key: false])
        #expect(!AdminRightPolicy(read: { value }, write: {}).isValid())
    }

    @Test func `boolean threshold is not an integer one`() throws {
        let value = try AdminRightDefinition(dictionary: ["class": "rule", "rule": AdminRightDefinition.delegateName, "k-of-n": true])
        #expect(!AdminRightPolicy(read: { value }, write: {}).isValid())
    }

    @Test(arguments: [0, 2, -1])
    func `other thresholds are rejected`(_ threshold: Int) throws {
        let value = try AdminRightDefinition(dictionary: ["class": "rule", "rule": AdminRightDefinition.delegateName, "k-of-n": threshold])
        #expect(!AdminRightPolicy(read: { value }, write: {}).isValid())
    }
}
