// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import LeakProbe

@main
private enum LeakProbeCLI {
    private static let usage = """
    leakprobe clock
    leakprobe system-resolve --nonce NONCE --record FILE
    leakprobe interface-index --name INTERFACE
    leakprobe selftest [--record FILE]
    leakprobe generate --config FILE --rounds N --state STATE --record FILE [--nonce NONCE]
    leakprobe listen --addresses IP,IP [--port 8088] [--dns-port 5354] --seconds N --record FILE
    generate/listen are VM commands. On the production host run selftest only.
    """

    static func main() async {
        do { try await execute() }
        catch {
            FileHandle.standardError.write(Data("leakprobe: \(error)\n".utf8))
            exit(1)
        }
    }

    private static func execute() async throws {
        var args = Array(CommandLine.arguments.dropFirst())
        guard !args.isEmpty else { FileHandle.standardOutput.write(Data((usage + "\n").utf8)); return }
        let command = args.removeFirst()
        if ["--help", "help"].contains(command) {
            FileHandle.standardOutput.write(Data((usage + "\n").utf8)); return
        }
        if try utility(command, arguments: args) {
            return
        }
        let options = try parse(args)
        let record: ProbeRunRecord
        switch command {
        case "selftest":
            guard Set(options.keys).isSubset(of: ["--record"]) else { throw ProbeError.configuration(usage) }
            record = try await ProbeSelfTest.run()
        case "generate": record = try await generate(options)
        case "listen": record = try await listen(options)
        default: throw ProbeError.configuration(usage)
        }
        let data = try ProbeRunRecord.canonicalData(record)
        if let path = options["--record"] {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
        FileHandle.standardOutput.write(data + Data("\n".utf8))
    }

    private static func utility(_ command: String, arguments: [String]) throws -> Bool {
        switch command {
        case "clock":
            guard arguments.isEmpty else { throw ProbeError.configuration(usage) }
            let data = try JSONSerialization.data(withJSONObject: ["timestamp": Date().timeIntervalSince1970])
            FileHandle.standardOutput.write(data + Data("\n".utf8))
        case "system-resolve":
            try systemResolve(parse(arguments))
        case "interface-index":
            let options = try parse(arguments)
            guard let name = options["--name"], name.utf8.allSatisfy({ (48 ... 122).contains($0) }) else {
                throw ProbeError.configuration(usage)
            }
            let data = try JSONSerialization.data(withJSONObject: ["index": if_nametoindex(name)])
            FileHandle.standardOutput.write(data)
        default: return false
        }
        return true
    }

    private static func systemResolve(_ options: [String: String]) throws {
        guard let nonce = options["--nonce"], let path = options["--record"] else { throw ProbeError.configuration(usage) }
        let name = try MarkerWire.systemResolverName(nonce: nonce)
        let data = try JSONSerialization.data(withJSONObject: ["timestamp": Date().timeIntervalSince1970, "nonce": nonce, "name": name])
        try data.write(to: URL(fileURLWithPath: path))
        var addresses: UnsafeMutablePointer<addrinfo>?
        _ = getaddrinfo(name, nil, nil, &addresses)
        if let addresses {
            freeaddrinfo(addresses)
        }
    }

    private static func parse(_ arguments: [String]) throws -> [String: String] {
        guard arguments.count.isMultiple(of: 2) else { throw ProbeError.configuration(usage) }
        var options: [String: String] = [:]
        for index in stride(from: 0, to: arguments.count, by: 2) {
            let key = arguments[index]
            guard key.hasPrefix("--"), options[key] == nil else { throw ProbeError.configuration(usage) }
            options[key] = arguments[index + 1]
        }
        return options
    }

    private static func generate(_ options: [String: String]) async throws -> ProbeRunRecord {
        guard Set(options.keys).isSubset(of: ["--config", "--rounds", "--state", "--record", "--nonce"]),
              let path = options["--config"], let count = options["--rounds"].flatMap(Int.init),
              let state = options["--state"], options["--record"] != nil
        else { throw ProbeError.configuration(usage) }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let configuration = try JSONDecoder().decode(ProbeConfiguration.self, from: data)
        let nonce = options["--nonce"] ?? UUID().uuidString.lowercased()
        let start = Date().timeIntervalSince1970
        let observations = try await MarkerGenerator.run(configuration: configuration, nonce: nonce, rounds: count)
        return try ProbeRunRecord(
            nonce: nonce,
            configuration: configuration,
            observations: observations,
            windows: [ObservationWindow(
                state: state,
                start: start,
                end: Date().timeIntervalSince1970,
                receiversComplete: false,
            )],
            inputHashes: ["configurationFile": ProbeRunRecord.hash(data)],
        )
    }

    private static func listen(_ options: [String: String]) async throws -> ProbeRunRecord {
        guard Set(options.keys).isSubset(of: ["--addresses", "--port", "--dns-port", "--seconds", "--record"]),
              let addresses = options["--addresses"], let seconds = options["--seconds"].flatMap(Double.init), options["--record"] != nil,
              let port = UInt16(options["--port"] ?? "8088"), let dnsPort = UInt16(options["--dns-port"] ?? "5354")
        else { throw ProbeError.configuration(usage) }
        let listener = try MarkerListener(addresses: addresses.split(separator: ",").map(String.init), port: port, dnsPort: dnsPort)
        let received = try await listener.collect(seconds: seconds)
        // Listener records retain every marker; verdict selects the generator's nonce and time windows.
        return try ProbeRunRecord(nonce: "receiver", configuration: ProbeConfiguration(targets: listener.targets), observations: received)
    }
}
