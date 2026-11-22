// SPDX-License-Identifier: MIT
import Darwin
import Dispatch
import Foundation
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXDiagnostics

// This must precede argument handling and every adapter, listener and state-directory construction.
#if WGEX_LAB_BUILD
    guard LabGuard.isLabHost() else { exit(0) }
#elseif DEBUG
    if HostGuard.refuseOwnerMac() {
        WGEXLogger(category: .daemon).log("Debug daemon refused on a non-VM Mac")
        exit(0)
    }
#endif

private let arguments = CommandLine.arguments.dropFirst()
private let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
private let build = Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0") ?? 0
if arguments.contains("--version") || arguments.contains("--doctor") {
    #if WGEX_LAB_BUILD
        let labBuild = true
    #else
        let labBuild = false
    #endif
    let metadata = "WGEXDaemon \(version) (\(build)) protocol \(Envelope.currentProtocolVersion)\n"
        + "service=\(BuildIdentifiers.daemonService) team=\(BuildIdentifiers.current.team) labBuild=\(labBuild)\n"
    FileHandle.standardOutput.write(Data(metadata.utf8))
    exit(0)
}

guard arguments.isEmpty else { exit(64) }
try SystemStateAdapters.disableCoreDumps()
private let logger = WGEXLogger(category: .daemon)
do {
    #if WGEX_LAB_BUILD
        let engineFactory = LabGuardedEngineFactory()
    #else
        let engineFactory = SystemDaemonEngineFactory()
    #endif
    try await DaemonRuntime.runSystem(
        daemonVersion: version, daemonBuild: build, engineFactory: engineFactory,
        makeDiagnostics: { DaemonDiagnosticsAdapter.system(snapshot: $0) },
        log: { logger.log(LogMessage(stringLiteral: $0.rawValue)) },
        failure: { error, context in
            #if WGEX_LAB_BUILD
                logLabFailure(error, logger: logger, context: context)
            #endif
        },
    )
    exit(0)
} catch {
    // Do not log arbitrary adapter errors; they may contain private profile or system data.
    logger.log("Daemon state directory unusable or minimum build refused")
    #if WGEX_LAB_BUILD
        logLabFailure(error, logger: logger, context: "startup")
    #endif
    exit(78)
}

#if WGEX_LAB_BUILD
    /// Adapter errors can contain profile data; never render arbitrary descriptions into the log ring.
    @Sendable private func logLabFailure(_ error: any Error, logger: WGEXLogger, context: StaticString) {
        switch error {
        case let failure as DaemonFailure where failure.kind == .hostSystem:
            logger.log("Lab system adapter failure, code: \(PublicLogValue.count(Int(failure.systemStatus ?? -1)))")
        case DaemonFailure.hostLabRequired:
            logger.log("Lab host guard refused an adapter")
        default:
            DaemonDiagnostics.log(error, context: context)
            logger.log("Lab adapter failure; detailed data withheld")
        }
    }

#endif
