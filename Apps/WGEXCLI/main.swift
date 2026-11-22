// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonClient
import WGEXDaemonProtocol

/// Built on the production host; executed only in the VM lab.
private let client = DaemonClient(
    transport: NSXPCClientTransport(),
    clientVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1",
    clientBuild: Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1") ?? 1,
)
private let cli = WGEXCLICore(client: client, service: ServiceController())
private let result = await cli.run(Array(CommandLine.arguments.dropFirst()))
await client.disconnect()
FileHandle.standardOutput.write(Data(result.output.utf8))
exit(result.exitCode)
