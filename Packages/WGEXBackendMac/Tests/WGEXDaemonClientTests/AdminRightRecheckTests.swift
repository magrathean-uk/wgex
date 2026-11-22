// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Security
    import Testing
    @testable import WGEXDaemonProtocol

    /// The daemon's recheck (SystemDaemonAuthorisation) over the modelled read-back, not the host database.
    private struct AdminRightRecheckTests {
        private func recheck(_ authd: ModelledAuthd, _ form: Data?) -> Bool {
            DaemonAuthorisation.verifyExternalRight(form, policy: AdminRightPolicy.makeSystem(ports: authd.database), ports: authd.ports)
        }

        @Test func `the fixture is a rule class read back without shared or timeout`() throws {
            let right = try AdminRightReadback.right()
            #expect(right["class"] as? String == "rule")
            #expect(right["rule"] as? [String] == [AdminRightDefinition.delegateName])
            #expect(right["shared"] == nil && right["timeout"] == nil)
            #expect(right["comment"] as? String == AdminRightDefinition.canonicalDictionary["comment"] as? String)
            #expect(try AdminRightDefinition(dictionary: right) == .required)
            #expect(try AdminRightDefinition.acceptsDelegate(AdminRightReadback.delegate()))
        }

        @Test func `the daemon accepts the app's approval through the read back right`() throws {
            let authd = try ModelledAuthd.fixture()
            #expect(recheck(authd, authd.approve()))
            #expect(authd.recheckNames == [AuthorisationTable.adminRightName])
            #expect(authd.recheckFlags == [[]])
            #expect(authd.frees == 1)
        }

        @Test func `an approval older than the delegate timeout, or none, is refused`() throws {
            let authd = try ModelledAuthd.fixture()
            let form = authd.approve()
            authd.advance(Double(AdminRightDefinition.maximumDelegateTimeout))
            #expect(!recheck(authd, form))
            #expect(!recheck(authd, authd.unapproved()))
            #expect(!recheck(authd, Data(count: MemoryLayout<AuthorizationExternalForm>.size)))
            #expect(!recheck(authd, nil))
            let nonInteractive = authd.recheckFlags.allSatisfy(\.isEmpty)
            #expect(nonInteractive)
        }

        @Test func `the former zero timeout delegate fails at authd even when the policy admits it`() throws {
            let authd = try ModelledAuthd.fixture()
            try authd.set(AuthorisationTable.adminRightName, ["class": "rule", "rule": ["authenticate-admin"]])
            try authd.set("authenticate-admin", ["class": "user", "group": "admin", "shared": true, "timeout": 0])
            let lenient = AdminRightPolicy(read: { .required }, write: {})
            #expect(!DaemonAuthorisation.verifyExternalRight(authd.approve(), policy: lenient, ports: authd.ports))
            #expect(!recheck(authd, authd.approve()))
        }

        @Test func `a missing right or delegate is refused before any form is imported`() throws {
            for name in [AuthorisationTable.adminRightName, AdminRightDefinition.delegateName] {
                let authd = try ModelledAuthd.fixture()
                try authd.set(name, nil)
                #expect(!recheck(authd, authd.approve()))
                #expect(authd.recheckFlags.isEmpty && authd.frees == 0)
            }
        }

        @Test(arguments: [
            ["class": "allow"],
            ["class": "rule", "rule": ["allow"]],
            ["class": "rule", "rule": ["authenticate-admin-30"]],
            ["class": "user", "group": "admin", "shared": true, "timeout": 300],
            ["class": "rule", "rule": ["authenticate-admin-nonshared", "authenticate-session-owner"]],
        ] as [[String: any Sendable]])
        func `a weaker right is refused even though authd would grant it`(_ right: [String: any Sendable]) throws {
            let authd = try ModelledAuthd.fixture()
            try authd.set(AuthorisationTable.adminRightName, right)
            try authd.set("authenticate-admin-30", ["class": "user", "group": "admin", "shared": true, "timeout": 30])
            #expect(!recheck(authd, authd.approve()))
            #expect(authd.recheckFlags.isEmpty)
        }

        @Test(arguments: [
            ["class": "allow"],
            ["class": "user", "group": "admin", "shared": true, "timeout": 30],
            ["class": "user", "group": "admin", "shared": false, "timeout": 300],
        ] as [[String: any Sendable]])
        func `a weakened delegate is refused`(_ delegate: [String: any Sendable]) throws {
            let authd = try ModelledAuthd.fixture()
            try authd.set(AdminRightDefinition.delegateName, delegate)
            #expect(!recheck(authd, authd.approve()))
        }

        @Test func `root writes the canonical right and accepts only its read back`() throws {
            let authd = try ModelledAuthd.fixture()
            try authd.set(AuthorisationTable.adminRightName, ["class": "allow"])
            let policy = AdminRightPolicy.makeSystem(ports: authd.database)
            #expect(!policy.isValid())
            try policy.install()
            #expect(authd.writes == [AuthorisationTable.adminRightName])
            let stored = try #require(authd.definition(AuthorisationTable.adminRightName))
            #expect(stored["class"] as? String == "rule" && stored["shared"] == nil && stored["timeout"] == nil)
            #expect(try AdminRightDefinition(dictionary: stored) == .required)
            #expect(policy.isValid())
            #expect(recheck(authd, authd.approve()))
        }

        @Test func `a non root writer or an ineffective write fails closed`() throws {
            let authd = try ModelledAuthd.fixture()
            let notRoot = AdminRightPolicy.makeSystem(ports: .init(
                read: { authd.definition($0) },
                write: { _, _ in true },
                isRoot: { false },
            ))
            #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) { try notRoot.install() }
            try authd.set(AuthorisationTable.adminRightName, ["class": "allow"])
            let ineffective = AdminRightPolicy.makeSystem(ports: .init(
                read: { authd.definition($0) },
                write: { _, _ in true },
                isRoot: { true },
            ))
            #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) { try ineffective.install() }
        }
    }
#endif
