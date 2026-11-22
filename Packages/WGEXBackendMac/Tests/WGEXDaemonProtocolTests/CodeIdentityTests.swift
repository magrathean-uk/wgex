// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    @testable import WGEXDaemonProtocol

    private struct CodeIdentityTests {
        @Test(arguments: ["MacOS/WGEX", "MacOS/WGEXDaemon", "Helpers/wgex"])
        func `each executable resolves the shared app root`(_ path: String) throws {
            let executable = URL(fileURLWithPath: "/Applications/WGEX.app/Contents/\(path)")
            #expect(try CodeIdentity.bundleRoot(executableURL: executable).path == "/Applications/WGEX.app")
        }

        @Test
        func `an executable outside the bundle is refused`() {
            #expect(throws: DaemonFailure(code: .securityInvalidBundleLayout)) {
                try CodeIdentity.bundleRoot(executableURL: URL(fileURLWithPath: "/tmp/wgex"))
            }
        }

        @Test(arguments: [false, true], [false, true])
        func `fat headers enumerate every slice in either width and byte order`(_ wide: Bool, _ little: Bool) throws {
            var bytes = Data(repeating: 0, count: 256)
            let magic: [UInt8] = wide ? [0xCA, 0xFE, 0xBA, 0xBF] : [0xCA, 0xFE, 0xBA, 0xBE]
            bytes.replaceSubrange(0 ..< 4, with: little ? Array(magic.reversed()) : magic)
            bytes[little ? 4 : 7] = 2
            let stride = wide ? 32 : 20
            let width = wide ? 8 : 4
            bytes[8 + 8 + (little ? 0 : width - 1)] = 128
            bytes[8 + stride + 8 + (little ? 0 : width - 1)] = 192
            #expect(try CodeIdentity.sliceOffsets(in: bytes) == [128, 192])
            bytes[8 + 8 + (little ? 0 : width - 1)] = 0
            #expect(throws: DaemonFailure(code: .securityInvalidExecutable)) { try CodeIdentity.sliceOffsets(in: bytes) }
        }

        @Test
        func `thin binaries need no extra slices and malformed headers fail closed`() throws {
            #expect(try CodeIdentity.sliceOffsets(in: Data([0xCF, 0xFA, 0xED, 0xFE])) == [])
            for bytes in [
                Data(),
                Data([0xCA, 0xFE, 0xBA, 0xBE]),
                Data(repeating: 0, count: 8),
                Data([0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF]),
            ] {
                #expect(throws: DaemonFailure(code: .securityInvalidExecutable)) { try CodeIdentity.sliceOffsets(in: bytes) }
            }
        }

        @Test
        func `signing information keeps all hashes and deduplicates the running slice`() throws {
            let first = Data(repeating: 1, count: 20)
            let second = Data(repeating: 2, count: 20)
            #expect(try CodeIdentity.hashes(unique: first, additional: [first, second]) == [first, second])
            #expect(try CodeIdentity.hashes(unique: first, additional: []) == [first])
            #expect(throws: DaemonFailure(code: .securityMissingHash)) { try CodeIdentity.hashes(unique: nil, additional: [second]) }
            #expect(throws: DaemonFailure(code: .securityMissingHash)) { try CodeIdentity.hashes(unique: first, additional: [Data()]) }
        }
    }

    #if WGEX_LAB_BUILD
        private struct LabPeerRequirementsTests {
            private struct FixedIdentity: CodeIdentityReading {
                var hashes: [String: [Data]]
                func cdhashes(at url: URL) throws -> [Data] {
                    guard let result = hashes[url.path] else { throw DaemonFailure(code: .securityMissingHash) }
                    return result
                }
            }

            private let root = "/Applications/WGEX.app/Contents/"
            private let first = Data(repeating: 1, count: 20)
            private let second = Data(repeating: 2, count: 20)
            private let bundle = URL(fileURLWithPath: "/Applications/WGEX.app")

            @Test
            func `daemon admission pins the installed app and CLI and every supplied slice`() throws {
                let reader = FixedIdentity(hashes: [root + "MacOS/WGEX": [first, second], root + "Helpers/wgex": [second]])
                let result = LabPeerRequirements.installedClients(bundle: bundle, reader: reader)
                #expect(try result == (RequirementStrings.lab(identifierHashes: [
                    (BuildIdentifiers.current.app, [first, second]), (BuildIdentifiers.current.cli, [second]),
                ])))
            }

            @Test(arguments: [false, true])
            func `unreadable or empty installed binary is omitted without weakening the remaining peer`(_ empty: Bool) throws {
                var hashes = [root + "Helpers/wgex": [second]]
                if empty {
                    hashes[root + "MacOS/WGEX"] = []
                }
                let result = LabPeerRequirements.installedClients(bundle: bundle, reader: FixedIdentity(hashes: hashes))
                #expect(try result == (RequirementStrings.lab(identifierHashes: [(BuildIdentifiers.current.cli, [second])])))
            }

            @Test
            func `no readable installed binaries deny every connection`() {
                let result = LabPeerRequirements.installedClients(bundle: bundle, reader: FixedIdentity(hashes: [:]))
                #expect(result == RequirementStrings.labDenyAll)
            }

            @Test
            func `the reporter check pins the app alone and an invalid bundle layout denies all`() throws {
                let reader = FixedIdentity(hashes: [root + "MacOS/WGEX": [first], root + "Helpers/wgex": [second]])
                let result = LabPeerRequirements.app(executableURL: URL(fileURLWithPath: root + "MacOS/WGEXDaemon"), reader: reader)
                #expect(try result == (RequirementStrings.lab(identifierHashes: [(BuildIdentifiers.current.app, [first])])))
                #expect(LabPeerRequirements.app(executableURL: URL(fileURLWithPath: "/tmp/WGEXDaemon"), reader: reader)
                    == RequirementStrings.labDenyAll)
            }
        }
    #endif
#endif
