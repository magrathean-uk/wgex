// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct ProductionCompositionTests {
    private struct FixedSysctl: SysctlReading {
        let value: Int64?
        func integer(named name: String) -> Int64? {
            name == HypervisorPresence.sysctlName ? value : nil
        }
    }

    @Test(arguments: HostGuard.Configuration.allCases, [Int64(0), 1, 2, nil])
    func `configuration host decision table`(configuration: HostGuard.Configuration, hypervisor: Int64?) {
        for marker in [false, true] {
            let expected = configuration == .release || (hypervisor == 1 && (configuration == .debug || marker))
            #expect(HostGuard
                .permits(configuration: configuration, sysctl: FixedSysctl(value: hypervisor), labMarkerValid: marker) == expected)
        }
    }

    @Test
    func `system state root is permitted without a lab marker`() throws {
        let temporary = try StateDirectory.temporaryRoot()
        #expect(StateDirectory.permits(path: "/Library/Application Support/WGEX", temporaryRoot: temporary.path))
        #expect(StateDirectory.permits(path: "/System/Volumes/Data/Library/Application Support/WGEX", temporaryRoot: temporary.path))
        #expect(!StateDirectory.permits(path: "/Library/Application Support/WGEX-other", temporaryRoot: temporary.path))
        let parent = temporary.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("WGEX")
        let directory = try StateDirectory(root: root)
        try directory.replace("state", with: Data([1]))
        #expect(try directory.read("state") == Data([1]))
    }

    @Test
    func `table expansion preserves the immutable production baseline rules`() throws {
        let root = try #require(Bundle.module.url(forResource: "Fixtures", withExtension: nil))
        let capture = root.appendingPathComponent("ProductionPF9f18703")
        let fixtures = root.appendingPathComponent("PacketFilterGoldens")
        let names = try FileManager.default.contentsOfDirectory(atPath: capture.path).filter { $0.hasSuffix(".pf") }
        #expect(names.count == 24)
        for name in names {
            let baseline = try String(contentsOf: capture.appendingPathComponent(name), encoding: .utf8)
            let current = try String(contentsOf: fixtures.appendingPathComponent(name), encoding: .utf8)
            #expect(expandTable(current) == baseline)
        }
    }

    private func expandTable(_ text: String) -> String {
        var ranges: [String] = [], result: [String] = []
        for line in text.split(separator: "\n").map(String.init) {
            if line.hasPrefix("table <"), let start = line.range(of: " const { ") {
                ranges = line[start.upperBound...].dropLast(2).components(separatedBy: ", ")
            } else if let start = line.range(of: "<wgex_") {
                result += ranges.map { String(line[..<start.lowerBound]) + $0 }
            } else {
                result.append(line)
            }
        }
        return result.isEmpty ? "" : result.joined(separator: "\n") + "\n"
    }

    @Test(.enabled(if: SystemSysctl().integer(named: HypervisorPresence.sysctlName) == 0))
    func `the physical host is refused by the real read-only guard`() {
        #expect(HostGuard.refuseOwnerMac())
    }
}
