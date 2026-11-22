// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol
#if os(macOS)
    import Security
#endif

private struct RequirementStringsTests {
    /// Captured from 064b0dc for the standard Release identifiers, independently
    /// of the implementation that constructs the requirements.
    private static let releaseSnapshot = [
        #"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and "#
            + #"certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "ABCDE12345" "#
            + #"and (identifier "com.magrathean.WGEXApp") and !(entitlement["com.apple.security.get-task-allow"] exists)"#,
        #"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and "#
            + #"certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "ABCDE12345" "#
            + #"and (identifier "com.magrathean.WGEXApp.daemon") and !(entitlement["com.apple.security.get-task-allow"] exists)"#,
        #"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and "#
            + #"certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "ABCDE12345" "#
            + #"and (identifier "com.magrathean.WGEXApp" or identifier "com.magrathean.WGEXApp.cli") "#
            + #"and !(entitlement["com.apple.security.get-task-allow"] exists)"#,
    ]

    private static func strings(_ requirements: RequirementStrings) -> [String] {
        [requirements.appRequirement, requirements.daemonRequirement, requirements.clientRequirement]
    }

    private static var all: [String] {
        [
            RequirementStrings.debug.appRequirement, RequirementStrings.release.appRequirement,
            RequirementStrings.debug.daemonRequirement, RequirementStrings.debug.clientRequirement,
            RequirementStrings.release.daemonRequirement, RequirementStrings.release.clientRequirement,
        ]
    }

    @Test
    func `debug strings name the development base`() {
        let debug = RequirementStrings.debug
        #expect(debug.variant == .debug)
        #expect(debug.daemonRequirement.contains(".dev.daemon\""))
        #expect(debug.clientRequirement.contains(".dev\""))
        #expect(debug.clientRequirement.contains(".dev.cli\""))
    }

    @Test
    func `release strings never contain the development base`() {
        let release = RequirementStrings.release
        #expect(release.variant == .release)
        #expect(!release.daemonRequirement.contains(".dev"))
        #expect(!release.clientRequirement.contains(".dev"))
        #expect(release.daemonRequirement.contains("1.2.840.113635.100.6.2.6"))
        #expect(release.daemonRequirement.contains("1.2.840.113635.100.6.1.13"))
        #expect(release.daemonRequirement.contains("get-task-allow"))
    }

    @Test
    func `release APIs preserve the exact baseline requirements`() {
        let identifiers = BuildIdentifiers(base: "com.magrathean.WGEXApp", team: "ABCDE12345")
        #expect(Self.strings(RequirementStrings.release) == Self.releaseSnapshot)
        #expect(Self.strings(RequirementStrings(identifiers: identifiers)) == Self.releaseSnapshot)
        #expect(Self.strings(RequirementStrings(identifiers: identifiers, variant: .release)) == Self.releaseSnapshot)
        #if !WGEX_LAB_BUILD && !WGEX_OWN_MAC_BUILD
            if RequirementStrings.current.identifiers == identifiers {
                #expect(Self.strings(RequirementStrings.current) == Self.releaseSnapshot)
            }
        #endif
    }

    #if !WGEX_LAB_BUILD && !WGEX_OWN_MAC_BUILD
        @Test
        func `current selector preserves the Release baseline for explicit identifiers`() {
            let identifiers = BuildIdentifiers(base: "com.magrathean.WGEXApp", team: "ABCDE12345")
            let requirements = RequirementStrings.current(for: identifiers)
            #expect(requirements.variant == .release)
            #expect(Self.strings(requirements) == Self.releaseSnapshot)
        }
    #endif

    @Test
    func `current uses the selector for current identifiers`() {
        #expect(RequirementStrings.current == RequirementStrings.current(for: .current))
    }

    @Test
    func `debug requirements retain the baseline policy`() {
        #expect(Self.strings(RequirementStrings.debug) == [
            #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and (identifier "com.magrathean.WGEXApp.dev")"#,
            #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and (identifier "com.magrathean.WGEXApp.dev.daemon")"#,
            #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and "#
                + #"(identifier "com.magrathean.WGEXApp.dev" or identifier "com.magrathean.WGEXApp.dev.cli")"#,
        ])
    }

    @Test
    func `every string names the team`() {
        for requirement in Self.all {
            #expect(requirement.contains("certificate leaf[subject.OU] = \"\(BuildIdentifiers.current.team)\""))
        }
    }

    @Test
    func `debug and release use different Mach services`() {
        #expect(RequirementStrings.debug.identifiers.daemonService != RequirementStrings.release.identifiers.daemonService)
    }

    #if os(macOS)
        @Test(arguments: all)
        func `the Security framework parses every string`(requirement: String) {
            var parsed: SecRequirement?
            let status = SecRequirementCreateWithString(requirement as CFString, [], &parsed)
            #expect(status == errSecSuccess)
            #expect(parsed != nil)
        }

        @Test
        func `a malformed string is rejected by the parser`() {
            var parsed: SecRequirement?
            let status = SecRequirementCreateWithString("identifier \"unterminated" as CFString, [], &parsed)
            #expect(status != errSecSuccess)
        }
    #endif
}

#if WGEX_OWN_MAC_BUILD
    private struct OwnMacRequirementStringsTests {
        private static let identifiers = BuildIdentifiers(base: "com.magrathean.WGEXApp", team: "ABCDE12345")
        private static let developmentIdentifiers = BuildIdentifiers(base: "com.magrathean.WGEXApp.dev", team: "ABCDE12345")
        private static let snapshot = [
            #"anchor apple generic and certificate leaf[subject.OU] = "\#(OwnMacIdentity.team)" "#
                + #"and certificate leaf[subject.CN] = "\#(OwnMacIdentity.leaf)" "#
                + #"and (identifier "com.magrathean.WGEXApp") and !(entitlement["com.apple.security.get-task-allow"] exists)"#,
            #"anchor apple generic and certificate leaf[subject.OU] = "\#(OwnMacIdentity.team)" "#
                + #"and certificate leaf[subject.CN] = "\#(OwnMacIdentity.leaf)" "#
                + #"and (identifier "com.magrathean.WGEXApp.daemon") and !(entitlement["com.apple.security.get-task-allow"] exists)"#,
            #"anchor apple generic and certificate leaf[subject.OU] = "\#(OwnMacIdentity.team)" "#
                + #"and certificate leaf[subject.CN] = "\#(OwnMacIdentity.leaf)" "#
                + #"and (identifier "com.magrathean.WGEXApp" or identifier "com.magrathean.WGEXApp.cli") "#
                + #"and !(entitlement["com.apple.security.get-task-allow"] exists)"#,
        ]

        private static func strings(_ requirements: RequirementStrings) -> [String] {
            [requirements.appRequirement, requirements.daemonRequirement, requirements.clientRequirement]
        }

        @Test
        func `own Mac requirements match the exact policy`() {
            let requirements = RequirementStrings.current(for: Self.identifiers)
            #expect(requirements.variant == .ownMac)
            #expect(Self.strings(requirements) == Self.snapshot)
            #expect(Self.strings(RequirementStrings(identifiers: Self.identifiers, variant: .ownMac)) == Self.snapshot)
        }

        @Test
        func `own Mac selection preserves the Debug policy`() {
            let identifiers = Self.developmentIdentifiers
            let requirements = RequirementStrings.current(for: identifiers)
            #expect(requirements.variant == .debug)
            #expect(requirements == RequirementStrings(identifiers: identifiers, variant: .debug))
            #expect(Self.strings(requirements) == [
                #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and (identifier "com.magrathean.WGEXApp.dev")"#,
                #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and (identifier "com.magrathean.WGEXApp.dev.daemon")"#,
                #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and "#
                    + #"(identifier "com.magrathean.WGEXApp.dev" or identifier "com.magrathean.WGEXApp.dev.cli")"#,
            ])
        }

        @Test
        func `own Mac policy pins the identity team identifiers and absence of debugging entitlement`() {
            // String-level checks: offline tests have no Apple-signed fixture identities.
            let requirements = RequirementStrings.current(for: Self.identifiers)
            for requirement in Self.strings(requirements) {
                #expect(requirement.contains("anchor apple generic"))
                #expect(requirement.contains(#"certificate leaf[subject.OU] = "\#(OwnMacIdentity.team)""#))
                #expect(requirement.contains(#"certificate leaf[subject.CN] = "\#(OwnMacIdentity.leaf)""#))
                #expect(requirement.contains(#"!(entitlement["com.apple.security.get-task-allow"] exists)"#))
            }
            let otherTeam = BuildIdentifiers(base: Self.identifiers.base, team: "OTHERTEAM0")
            #expect(Self.strings(RequirementStrings.current(for: otherTeam)) == Self.snapshot)
            #expect(!requirements.appRequirement.contains(#"identifier "com.magrathean.WGEXApp.cli""#))
            #expect(!requirements.daemonRequirement.contains(#"identifier "com.magrathean.WGEXApp.cli""#))
            #expect(!requirements.clientRequirement.contains(#"identifier "com.magrathean.WGEXApp.daemon""#))
        }

        @Test
        func `current preserves Debug and selects own Mac for Release identifiers`() {
            let current = RequirementStrings.current
            if current.identifiers.isDevelopment {
                #expect(current.variant == .debug)
                #expect(current == RequirementStrings.debug)
            } else {
                #expect([current.appRequirement, current.daemonRequirement, current.clientRequirement] == Self.snapshot)
            }
        }

        #if os(macOS)
            @Test
            func `Security parses each own Mac requirement`() {
                for requirement in Self.strings(RequirementStrings.current(for: Self.identifiers)) {
                    var parsed: SecRequirement?
                    #expect(SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess)
                    #expect(parsed != nil)
                }
            }
        #endif
    }
#endif

#if WGEX_LAB_BUILD
    private struct LabRequirementStringsTests {
        @Test
        func `lab variant is current while debug and release retain certificate requirements`() {
            #expect(RequirementStrings.current.variant == .lab)
            #expect(RequirementStrings.current.clientRequirement == RequirementStrings.labDenyAll)
            #expect(RequirementStrings.current.daemonRequirement == RequirementStrings.labDenyAll)
            #expect(RequirementStrings.current.appRequirement == RequirementStrings.labDenyAll)
            for base in ["com.magrathean.WGEXApp", "com.magrathean.WGEXApp.dev"] {
                let identifiers = BuildIdentifiers(base: base, team: "ABCDE12345")
                let requirements = RequirementStrings.current(for: identifiers)
                #expect(requirements.identifiers == identifiers)
                #expect(requirements.variant == .lab)
                #expect(requirements.appRequirement == RequirementStrings.labDenyAll)
                #expect(requirements.daemonRequirement == RequirementStrings.labDenyAll)
                #expect(requirements.clientRequirement == RequirementStrings.labDenyAll)
            }
        }

        @Test
        func `one hash has exact lowercase Apple requirement syntax`() throws {
            let requirement = try RequirementStrings.lab(identifierHashes: [("com.example.app", [Data(repeating: 0xAB, count: 20)])])
            #expect(requirement == "(identifier \"com.example.app\" and cdhash H\"abababababababababababababababababababab\")")
            #expect(!requirement.contains("anchor"))
            #expect(!requirement.contains("certificate"))
        }

        @Test
        func `several peers and slices are joined with or`() throws {
            let first = Data(repeating: 0x01, count: 20)
            let second = Data(repeating: 0xFE, count: 20)
            let requirement = try RequirementStrings.lab(identifierHashes: [("app", [first, second]), ("cli", [second])])
            #expect(requirement == "(identifier \"app\" and cdhash H\"0101010101010101010101010101010101010101\") or "
                + "(identifier \"app\" and cdhash H\"fefefefefefefefefefefefefefefefefefefefe\") or "
                + "(identifier \"cli\" and cdhash H\"fefefefefefefefefefefefefefefefefefefefe\")")
        }

        @Test
        func `a missing sibling hash throws even when another peer has a hash`() {
            #expect(throws: DaemonFailure(code: .securityLabMissingHash)) {
                try RequirementStrings.lab(identifierHashes: [("app", [Data(repeating: 1, count: 20)]), ("cli", [])])
            }
        }

        @Test(arguments: [0, 19, 21, 32])
        func `malformed hash lengths fail closed`(_ count: Int) {
            #expect(throws: DaemonFailure(code: .securityLabInvalidHash)) {
                try RequirementStrings.lab(identifierHashes: [("app", [Data(repeating: 1, count: count)])])
            }
        }

        @Test
        func `identifiers cannot inject a requirement`() {
            #expect(throws: DaemonFailure(code: .securityLabInvalidIdentifier)) {
                try RequirementStrings.lab(identifierHashes: [("app\" or true", [Data(repeating: 1, count: 20)])])
            }
        }

        @Test
        func `no peers produce an impossible requirement`() throws {
            #expect(try RequirementStrings.lab(identifierHashes: []) == "cdhash H\"0000000000000000000000000000000000000000\"")
        }

        #if os(macOS)
            @Test
            func `Security parses pinned peers and deny all`() throws {
                let requirement = try RequirementStrings.lab(identifierHashes: [("app", [Data(repeating: 0xAB, count: 20)])])
                for string in [requirement, RequirementStrings.labDenyAll] {
                    var parsed: SecRequirement?
                    #expect(SecRequirementCreateWithString(string as CFString, [], &parsed) == errSecSuccess)
                    #expect(parsed != nil)
                }
            }
        #endif
    }
#endif
