// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXDaemonProtocol

private struct AdminRightPolicyTests {
    @Test(arguments: ["allow", "deny", "authenticate-session-owner", "authenticate-admin", "authenticate-admin-30"])
    func `precreated permissive or different rules are refused`(rule: String) {
        let policy = AdminRightPolicy(read: { .init(ruleClass: "rule", rules: [rule]) }, write: {})
        #expect(!policy.isValid())
    }

    @Test
    func `the required right is the nonshared admin delegate without cache fields`() {
        #expect(AdminRightDefinition.required == .init(ruleClass: "rule", rules: ["authenticate-admin-nonshared"]))
        #expect(AdminRightDefinition.canonicalDictionary["class"] as? String == "rule")
        #expect(AdminRightDefinition.canonicalDictionary["rule"] as? [String] == ["authenticate-admin-nonshared"])
        #expect(AdminRightDefinition.canonicalDictionary["shared"] == nil && AdminRightDefinition.canonicalDictionary["timeout"] == nil)
        #expect(!AdminRightPolicy(read: { .init(ruleClass: "rule", rules: ["authenticate-admin-nonshared"], timeout: 300) }, write: {})
            .isValid())
    }

    @Test
    func `daemon replaces the definition and reads it back`() throws {
        let definition = Mutex(AdminRightDefinition(ruleClass: "allow", rules: [], shared: false, timeout: 0))
        let writes = Mutex(0)
        let policy = AdminRightPolicy(read: { definition.withLock { $0 } }, write: {
            writes.withLock { $0 += 1 }
            definition.withLock { $0 = .required }
        })
        try policy.install()
        #expect(policy.isValid())
        #expect(writes.withLock { $0 } == 1)
        definition.withLock { $0 = .init(ruleClass: "allow", rules: ["authenticate-admin"], shared: true, timeout: 300) }
        #expect(!policy.isValid())
    }

    @Test
    func `development builds use a separate admin right`() {
        #if DEBUG || WGEX_LAB_BUILD
            #expect(AuthorisationTable.adminRightName.hasSuffix(".manage-protection.dev"))
        #else
            #expect(!AuthorisationTable.adminRightName.hasSuffix(".dev"))
        #endif
    }
}
