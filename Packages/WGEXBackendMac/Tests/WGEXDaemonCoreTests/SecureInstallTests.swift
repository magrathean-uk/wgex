// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct SecureInstallTests {
    @Test
    func `root owned non writable entries and matching identities verify`() async {
        let system = FakeSecureInstallSystem()
        let port = SecureInstall(system: system)
        let report = await port.status()
        #expect(report.state == .verified)
        #expect(report.nonRootOwnedEntries == 0 && report.nonRootWritableEntries == 0)
        #expect(report.isUnderApplications && report.daemonIdentity == .matched && report.bundleIdentity == .matched)
        _ = await port.status()
        #expect(system.state.withLock { $0.identityChecks } == 1)
        system.state.withLock { $0.entries[1].mode = 0o757 }
        let changed = await port.status()
        #expect(changed.state == .needsAttention(.bundleWritable))
        #expect(changed.nonRootWritableEntries == 1)
        #expect(system.state.withLock { $0.identityChecks } == 2)
        system.state.withLock { $0.entries[1].changeStamp = "modified"; $0.identity.bundle = .failed }
        #expect(await port.status().state == .needsAttention(.identityMismatch))
        #expect(system.state.withLock { $0.identityChecks } == 3)
    }

    @Test
    func `perform repairs every entry as root wheel with readable modes`() async {
        let system = FakeSecureInstallSystem()
        system.state.withLock {
            $0.entries[0].uid = 501; $0.entries[0].gid = 20; $0.entries[0].mode = 0o700
            $0.entries[1].uid = 501; $0.entries[1].mode = 0o6777
            $0.entries.append(.init(relativePath: "Contents/Info.plist", uid: 501, gid: 20, mode: 0o600))
            $0.entries.append(.init(relativePath: "link", uid: 501, gid: 20, mode: 0o777, kind: .symlink))
        }
        let port = SecureInstall(system: system)
        #expect(await port.status().nonRootWritableEntries == 4)
        #expect(await port.perform().state == .verified)
        let entries = system.state.withLock { $0.entries }
        #expect(entries.allSatisfy { $0.uid == 0 && $0.gid == 0 })
        #expect(entries.map(\.mode) == [0o755, 0o755, 0o644, 0o777])
        #expect(system.state.withLock { $0.ownershipCalls } == ["link", "Contents/Info.plist", "Contents/MacOS/WGEXDaemon", "."])
        #expect(system.state.withLock { $0.modeCalls.map(\.0) } == ["Contents/Info.plist", "Contents/MacOS/WGEXDaemon", "."])
        #expect(await port.status().nonRootOwnedEntries == 0)
    }

    @Test(arguments: ["/tmp/WGEX.app", "/ApplicationsElsewhere/WGEX.app", "/Applications/../tmp/WGEX.app"])
    func `outside Applications refuses without mutation`(_ path: String) async {
        let system = FakeSecureInstallSystem()
        let port = SecureInstall(system: system, bundlePath: path)
        #expect(await port.perform().state == .needsAttention(.notInApplications))
        #expect(system.state.withLock { $0.ownershipCalls.isEmpty && $0.identityChecks == 0 })
    }

    @Test(arguments: [UInt16(0o700), 0o750, 0o600, 0o640, 0o1755, 0o4644])
    func `private or special modes fail verification and repair is read back`(mode: UInt16) async {
        let system = FakeSecureInstallSystem()
        system.state.withLock {
            $0.entries[0].mode = 0o700
            $0.entries[1].mode = mode
            $0.skipModeRepair = true
        }
        let port = SecureInstall(system: system)
        #expect(await port.status().state == .needsAttention(.inspectionFailed))
        #expect(await port.perform().state == .needsAttention(.inspectionFailed))
        system.state.withLock { $0.skipModeRepair = false }
        #expect(await port.perform().state == .verified)
        system.state.withLock { $0.entries[1].mode = mode }
        #expect(await port.status().state == .needsAttention(.inspectionFailed))
    }

    @Test
    func `descriptor repair opens private directories and executables without making resources executable`() throws {
        let manager = FileManager.default
        let root = try URL(fileURLWithPath: SecureBundleDescriptor.canonicalPath(manager.temporaryDirectory.path))
            .appendingPathComponent("wgex-modes-" + UUID().uuidString)
        defer { try? manager.removeItem(at: root) }
        let helpers = root.appendingPathComponent("Contents/Helpers")
        try manager.createDirectory(at: helpers, withIntermediateDirectories: true)
        let cli = helpers.appendingPathComponent("wgex")
        let resource = root.appendingPathComponent("Contents/Info.plist")
        try Data("inert executable fixture".utf8).write(to: cli)
        try Data("inert resource fixture".utf8).write(to: resource)
        for directory in [root, root.appendingPathComponent("Contents"), helpers] {
            try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: cli.path)
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: resource.path)
        let bundle = try SecureBundleDescriptor(path: root.path)
        defer { close(bundle.descriptor) }
        for entry in try bundle.entries().reversed() {
            try bundle.repair(entry, uid: getuid(), gid: getgid())
        }
        for entry in try bundle.entries() {
            #expect(entry.mode & 0o7777 == (entry.relativePath == "Contents/Info.plist" ? 0o644 : 0o755))
            #expect(entry.uid == getuid() && entry.gid == getgid())
            #expect(!entry.hasACL && !entry.aclWritable)
        }
    }

    @Test
    func `wrong bundle identity mismatch invalid entries and partial repair fail closed`() async {
        let system = FakeSecureInstallSystem()
        let port = SecureInstall(system: system)
        system.state.withLock { $0.executable = "/Applications/Other.app/Contents/MacOS/WGEXDaemon" }
        #expect(await port.perform().state == .needsAttention(.wrongBundle))
        system.state.withLock { $0.executable = "/Applications/WGEX.app/Contents/MacOS/WGEXDaemon"; $0.identity.daemon = .failed }
        #expect(await port.perform().state == .needsAttention(.identityMismatch))
        #expect(system.state.withLock { $0.ownershipCalls.isEmpty })
        let invalid = FakeSecureInstallSystem()
        invalid.state.withLock { $0.entries.append(.init(relativePath: "../outside", uid: 0, gid: 0, mode: 0o755)) }
        #expect(await SecureInstall(system: invalid).perform().state == .needsAttention(.inspectionFailed))
        let failing = FakeSecureInstallSystem()
        failing.state.withLock { $0.entries[1].uid = 501; $0.failRepair = true }
        #expect(await SecureInstall(system: failing).perform().state == .needsAttention(.inspectionFailed))
    }

    @Test
    func `non root owner without write permission is not verified`() async {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.entries[1].uid = 501; $0.entries[1].mode = 0o555 }
        let report = await SecureInstall(system: system).status()
        #expect(report.state == .needsAttention(.notRootOwned))
        #expect(report.nonRootOwnedEntries == 1 && report.nonRootWritableEntries == 0)
    }

    @Test
    func `temporary bundle enumeration never follows an external symlink`() async throws {
        let manager = FileManager.default
        let root = try URL(fileURLWithPath: SecureBundleDescriptor.canonicalPath(manager.temporaryDirectory.path))
            .appendingPathComponent("wgex-install-" + UUID().uuidString)
        defer { try? manager.removeItem(at: root) }
        let bundle = root.appendingPathComponent("WGEX.app")
        let external = root.appendingPathComponent("outside")
        try manager.createDirectory(at: bundle.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        try Data("inert fixture".utf8).write(to: bundle.appendingPathComponent("Contents/MacOS/WGEXDaemon"))
        try manager.createDirectory(at: external, withIntermediateDirectories: true)
        let sentinel = external.appendingPathComponent("sentinel")
        try Data("unchanged".utf8).write(to: sentinel)
        try manager.createSymbolicLink(at: bundle.appendingPathComponent("link"), withDestinationURL: external)
        let adapter = try TemporarySecureInstallSystem(root: bundle)
        let entries = try adapter.entries(bundlePath: bundle.path)
        #expect(entries.map(\.relativePath) == [".", "Contents", "Contents/MacOS", "Contents/MacOS/WGEXDaemon", "link"])
        #expect(entries.last?.kind == .symlink)
        #expect(try Data(contentsOf: sentinel) == Data("unchanged".utf8))
        let fake = FakeSecureInstallSystem()
        fake.state.withLock { $0.entries = entries }
        #expect(await SecureInstall(system: fake).perform().state == .verified)
        #expect(fake.state.withLock { $0.ownershipCalls.count } == entries.count)
        #expect(!fake.state.withLock { $0.ownershipCalls.contains { $0.contains("sentinel") } })
        #expect(try Data(contentsOf: sentinel) == Data("unchanged".utf8))
        #expect(throws: (any Error).self) { _ = try TemporarySecureInstallSystem(root: URL(fileURLWithPath: "/Applications/WGEX.app")) }
        #expect(throws: (any Error).self) { _ = try adapter.entries(bundlePath: external.path) }
        try manager.createSymbolicLink(at: root.appendingPathComponent("Alias.app"), withDestinationURL: bundle)
        #expect(throws: (any Error).self) { _ = try SecureBundleDescriptor(path: root.appendingPathComponent("Alias.app").path) }
    }
}
