// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDiagnostics
import WGEXPairing
import WGEXProfileStore
import WGEXTesting

/// In-process campaign driver. Usage: `swift-fuzz <repo-root> <seconds-per-target> <seed> <pending-dir>`.
/// Output is counts and vector names only; vector bytes are never printed.
@main
private enum Driver {
    private static let deadlineNanoseconds: UInt64 = 50_000_000
    private static let targets = ["parser", "stats", "endpoint", "cidr", "original", "profile", "pairing", "qr", "redactor", "zip"]

    private static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 5, let seconds = Double(args[2]), seconds > 0, seconds.isFinite, let seed = UInt64(args[3]) else {
            throw DriverError.arguments
        }
        let root = URL(fileURLWithPath: args[1])
        let reproducers = root.appendingPathComponent("Tests/Fixtures/fuzz/reproducers")
        let pending = try PendingVector(directory: URL(fileURLWithPath: args[4]))
        let watchdog = Watchdog(reproducers: reproducers)
        watchdog.start()
        let (seeds, fixtureKey) = try makeSeeds(root)
        var registered = SecretScanner()
        try fixtureKey.rawValue.withUnsafeBytes { raw in
            let key = try SecretBytes(copying: raw)
            registered.register(key)
        }
        var controlRandom = SeededRandom(seed: seed)
        let keyControl = Mutator.mutate([], operation: 8, fixtureKey: fixtureKey, random: &controlRandom)
        guard Data(keyControl).range(of: Data(fixtureKey.base64.utf8)) != nil,
              Oracles.registeredKeyLeaked(fixtureKey.base64, scanner: registered),
              Oracles.registeredKeyLeaked("prefix" + fixtureKey.base64 + "suffix", scanner: registered),
              !Oracles.registeredKeyLeaked(Redactor().redact(fixtureKey.base64), scanner: registered)
        else { write("fixture-key control failed"); exit(1) }
        let stats = seeds["stats"]?.first ?? []
        var campaign = Campaign(seed: seed, pending: pending, watchdog: watchdog, reproducers: reproducers, registered: registered)
        let started = DispatchTime.now().uptimeNanoseconds
        var random = SeededRandom(seed: seed)
        for target in targets {
            try campaign.runTarget(
                target, vectors: seeds[target] ?? [], stats: stats, fixtureKey: fixtureKey,
                seconds: seconds, random: &random,
            )
        }
        try replay(reproducers, campaign: &campaign)
        pending.clear(); let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1e9
        campaign.report(elapsed: elapsed)
        exit(campaign.findings.isEmpty ? 0 : 1)
    }

    private static func replay(_ reproducers: URL, campaign: inout Campaign) throws {
        // Every saved regression vector is replayed after the seeded campaign.
        for file in try namedFixtures(reproducers, extension: "bin") {
            let target = targets.first { file.name.hasPrefix($0 + "-") } ?? "stats"
            try campaign.run(
                target: target,
                name: "replay-\(file.name)",
                operation: "replay",
                bytes: file.bytes,
                mustAccept: file.name.contains("positive-control-rejected"),
                save: false,
            )
        }
    }

    private static func makeSeeds(_ root: URL) throws -> ([String: [[UInt8]]], PublicKey) {
        let configurations = try fixtures(root.appendingPathComponent("Tests/Fixtures/conf"), extension: "conf")
        let stats = try Array(Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/fuzz/stats-golden.json")))
        let fixtureProfile = TunnelProfile(
            id: UUID(uuid: (0, 0, 0, 0, 0, 0, 64, 0, 128, 0, 0, 0, 0, 0, 0, 1)),
            name: "Fuzz fixture", createdAt: Date(timeIntervalSince1970: 0),
        )
        let profile = try Array(ProfileDocument(profile: fixtureProfile).encoded())
        let pairing = try Array(PairingMessage(.ack, []).encoded())
        let fixture = try String(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/server.pub"), encoding: .utf8)
        guard let encodedKey = fixture.split(separator: "\n").first(where: { !$0.hasPrefix("#") && !$0.isEmpty })
        else { throw DriverError.arguments }
        let publicKey = try PublicKey(base64: String(encodedKey))
        let invitation = try PairingInvitation(sessionID: "00000000-0000-4000-8000-000000000000", publicKey: publicKey.rawValue)
        let zipSeeds = try fixtures(root.appendingPathComponent("Tests/Fixtures/fuzz/zip"), extension: "zip")
        return ([
            "parser": configurations, "original": configurations, "stats": [stats],
            "endpoint": [Array("[2001:db8::1]:51820".utf8), Array("peer.example.test:443".utf8)],
            "cidr": [Array("192.0.2.7/24".utf8), Array("2001:db8::7/64".utf8)],
            "profile": [profile], "pairing": [pairing], "qr": [Array(PairingQRCodec.encode(invitation).utf8)],
            "redactor": redactionSeeds(publicKey), "zip": zipSeeds,
        ], publicKey)
    }

    private static func redactionSeeds(_ key: PublicKey) -> [[UInt8]] {
        let base64 = key.base64
        let unpadded = String(base64.dropLast())
        let url = unpadded.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let hex = key.rawValue.map { String(format: "%02x", $0) }.joined()
        return [base64, unpadded, url, hex].map { Array(("x=" + $0).utf8) }
    }

    private static func write(_ message: String) {
        FileHandle.standardOutput.write(Data((message + "\n").utf8))
    }

    private static func fixtures(_ directory: URL, extension pathExtension: String) throws -> [[UInt8]] {
        try namedFixtures(directory, extension: pathExtension).map(\.bytes)
    }

    private static func namedFixtures(_ directory: URL, extension pathExtension: String) throws -> [(name: String, bytes: [UInt8])] {
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == pathExtension }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        return try files.map { try ($0.deletingPathExtension().lastPathComponent, Array(Data(contentsOf: $0))) }
    }

    fileprivate enum DriverError: Error { case arguments }

    /// Per-campaign counters and the 50 ms deadline policy.
    private struct Campaign {
        let seed: UInt64
        let pending: PendingVector
        let watchdog: Watchdog
        let reproducers: URL
        let registered: SecretScanner
        var counts: [String: [String: Int]] = [:]
        var durations: [String: [UInt64]] = [:]
        var slowest: [String: (nanoseconds: UInt64, size: Int, operation: String)] = [:]
        var findings: [String] = []
        var executed = 0

        init(seed: UInt64, pending: PendingVector, watchdog: Watchdog, reproducers: URL, registered: SecretScanner) {
            self.seed = seed; self.pending = pending; self.watchdog = watchdog; self.reproducers = reproducers
            self.registered = registered
        }

        mutating func runTarget(
            _ target: String, vectors: [[UInt8]], stats: [UInt8], fixtureKey: PublicKey,
            seconds: Double, random: inout SeededRandom,
        ) throws {
            guard !vectors.isEmpty else { throw DriverError.arguments }
            let targetStart = ContinuousClock.now
            var index = 0
            // Exercise every unmutated seed as well as mutations; round-trip oracles must see valid inputs.
            for bytes in vectors {
                try run(
                    target: target,
                    name: "seed-\(index)",
                    operation: "seed",
                    bytes: bytes,
                    mustAccept: !["parser", "original"].contains(target),
                )
                index += 1
            }
            repeat {
                let seedBytes = vectors[random.index(vectors.count)]
                let (bytes, operation) = Mutator.mutateStack(
                    seedBytes, first: index % Mutator.names.count, fixtureKey: fixtureKey, random: &random,
                )
                try run(target: target, name: "s\(seed)-i\(index)", operation: operation, bytes: bytes)
                if target == "stats", index.isMultiple(of: 8) {
                    try run(
                        target: target,
                        name: "control-i\(index)",
                        operation: "secret-control",
                        bytes: Mutator.secretControl(stats, index: index),
                        mustReject: true,
                    )
                }
                index += 1
            } while targetStart.duration(to: .now) < .seconds(seconds)
            Driver.write("completed \(target): vectors=\(index) smoke-seconds=\(seconds)")
        }

        mutating func run(
            target: String,
            name: String,
            operation: String,
            bytes: [UInt8],
            mustReject: Bool = false,
            mustAccept: Bool = false,
            save: Bool = true,
        ) throws {
            try pending.record(name: "\(target)-crash-\(name)", bytes: bytes)
            executed += 1
            // The reference oracle runs outside the timed call.
            let referenceSecret = target == "stats" && Oracles.containsSecretMember(bytes)
            var result = ""
            var best = UInt64.max
            // A vector over the deadline is retried twice so scheduler noise is not a finding.
            for _ in 0 ..< 3 {
                watchdog.begin(name: "\(target)-hang-\(name)", bytes: bytes)
                let start = DispatchTime.now().uptimeNanoseconds
                result = evaluate(target, bytes: bytes, mustReject: mustReject, referenceSecret: referenceSecret)
                best = min(best, DispatchTime.now().uptimeNanoseconds - start)
                watchdog.end()
                if best <= Driver.deadlineNanoseconds {
                    break
                }
            }
            if mustAccept, result == "rejected" {
                result = "positive-control-rejected"
            }
            if best > Driver.deadlineNanoseconds {
                result = "deadline-exceeded"
            }
            counts[target, default: [:]][result, default: 0] += 1
            if durations[target, default: []].count < 100_000 {
                durations[target, default: []].append(best)
            }
            if best > slowest[target]?.nanoseconds ?? 0 {
                slowest[target] = (best, bytes.count, operation)
            }
            guard !["accepted", "rejected"].contains(result) else { return }
            findings.append("\(name) \(operation) \(result)")
            if save {
                try Data(bytes).write(to: reproducers.appendingPathComponent("\(target)-\(result)-\(name).bin"))
            }
        }

        private func evaluate(_ target: String, bytes: [UInt8], mustReject: Bool, referenceSecret: Bool) -> String {
            switch target {
            case "parser": Oracles.parser(bytes, wiping: executed.isMultiple(of: 2))
            case "stats": Oracles.stats(bytes, mustReject: mustReject, referenceSecret: referenceSecret)
            default: Oracles.evaluate(target, bytes: bytes, registered: registered)
            }
        }

        func report(elapsed: Double) {
            for target in Driver.targets {
                let summary = (counts[target] ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
                let total = (counts[target] ?? [:]).values.reduce(0, +)
                let sorted = (durations[target] ?? []).sorted()
                let p99 = sorted.isEmpty ? 0 : Double(sorted[sorted.count * 99 / 100]) / 1e6
                let slow = slowest[target] ?? (0, 0, "")
                Driver.write("\(target): vectors=\(total) \(summary) p99-ms=\(String(format: "%.3f", p99))"
                    +
                    " slowest-ms=\(String(format: "%.3f", Double(slow.nanoseconds) / 1e6)) slowest-bytes=\(slow.size) slowest-ops=\(slow.operation)")
            }
            Driver.write("findings=\(findings.count) elapsed-s=\(String(format: "%.2f", elapsed))")
            for finding in findings {
                Driver.write("finding: \(finding)")
            }
        }
    }
}
