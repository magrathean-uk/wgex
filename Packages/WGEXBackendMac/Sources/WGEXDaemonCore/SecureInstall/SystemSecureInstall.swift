// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol
#if os(macOS)
    import Security
#endif

/// Production secure-install adapter. Lab builds additionally require all three lab guard conditions.
public struct SystemSecureInstall: SecureInstallSystem {
    private let bundlePath = "/Applications/WGEX.app"
    private let executablePath: String
    #if os(macOS) && WGEX_LAB_BUILD
        private let labIdentity: LabInstalledIdentity
    #else
        private let appRequirement: String
        private let daemonRequirement: String
    #endif

    /// Release pins the expected identities for the installed daemon bundle; Lab builds measure them at each check.
    public init() throws {
        try Self.requireHost()
        #if os(macOS)
            guard let executable = Bundle.main.executableURL else { throw DaemonFailure.hostSystem(EINVAL) }
            executablePath = executable.path
            guard try CodeIdentity.bundleRoot(executableURL: executable).path == bundlePath,
                  executablePath == bundlePath + "/Contents/MacOS/WGEXDaemon" else { throw DaemonFailure.hostSystem(EINVAL) }
            #if WGEX_LAB_BUILD
                // Measured at each identity check, like the Lab listener's client admission (DEC-013), so a compatible
                // update installed under this daemon is checked against what is installed now; nothing is pinned here.
                labIdentity = LabInstalledIdentity(check: Self.check)
            #else
                appRequirement = RequirementStrings.current.appRequirement
                daemonRequirement = RequirementStrings.current.daemonRequirement
            #endif
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    private static func requireHost() throws {
        #if WGEX_LAB_BUILD
            guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
        #endif
    }

    /// Returns the validated installed daemon executable path.
    public func daemonExecutablePath() throws -> String {
        try Self.requireHost()
        #if os(macOS)
            var info = stat()
            guard lstat(executablePath, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
                throw DaemonFailure.hostSystem(EINVAL)
            }
            return executablePath
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Enumerates entries through the no-follow bundle descriptor.
    public func entries(bundlePath: String) throws -> [SecureInstallEntry] {
        try Self.requireHost()
        #if os(macOS)
            let bundle = try openBundle(bundlePath)
            defer { close(bundle.descriptor) }
            return try bundle.entries()
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Inspects the replaceable bundle's parent, including its ACL, on every status call.
    public func ancestors(bundlePath: String) throws -> [SecureInstallEntry] {
        try Self.requireHost()
        guard bundlePath == self.bundlePath else { throw DaemonFailure.hostSystem(EINVAL) }
        let parent = try SecureBundleDescriptor(path: "/Applications")
        defer { close(parent.descriptor) }
        return try [parent.rootEntry(ancestor: true)]
    }

    /// Removes unsafe permissions before changing ownership on the same descriptor.
    public func repair(_ entry: SecureInstallEntry, bundlePath: String) throws {
        try Self.requireHost()
        #if os(macOS)
            let bundle = try openBundle(bundlePath)
            defer { close(bundle.descriptor) }
            try bundle.repair(entry, uid: 0, gid: 0)
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Legacy split repair calls are refused; production always uses the atomic descriptor operation.
    public func chown(_: SecureInstallEntry, bundlePath _: String, uid _: UInt32, gid _: UInt32) throws {
        throw DaemonFailure.hostSystem(EPERM)
    }

    /// Legacy split repair calls are refused; production always uses the atomic descriptor operation.
    public func chmod(_: SecureInstallEntry, bundlePath _: String, mode _: UInt16) throws {
        throw DaemonFailure.hostSystem(EPERM)
    }

    /// Checks both bundle and daemon against their signing requirements: pinned in Release, measured now in Lab builds.
    public func checkIdentity(bundlePath: String, daemonPath: String) throws -> SecureInstallIdentity {
        try Self.requireHost()
        #if os(macOS)
            guard bundlePath == self.bundlePath, daemonPath == executablePath else { throw DaemonFailure.hostSystem(EINVAL) }
            #if WGEX_LAB_BUILD
                return labIdentity.identity(bundlePath: bundlePath, daemonPath: daemonPath)
            #else
                return SecureInstallIdentity(
                    bundle: Self.check(path: bundlePath, requirement: appRequirement),
                    daemon: Self.check(path: daemonPath, requirement: daemonRequirement),
                )
            #endif
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    #if os(macOS)
        private func openBundle(_ path: String) throws -> SecureBundleDescriptor {
            guard path == bundlePath else { throw DaemonFailure.hostSystem(EINVAL) }
            return try SecureBundleDescriptor(path: path)
        }

        private static func check(path: String, requirement: String) -> SecureInstallReport.IdentityCheck {
            var code: SecStaticCode?
            var rule: SecRequirement?
            guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
                  SecRequirementCreateWithString(requirement as CFString, [], &rule) == errSecSuccess, let rule else { return .failed }
            let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
            return SecStaticCodeCheckValidity(code, flags, rule) == errSecSuccess ? .matched : .failed
        }
    #endif
}
