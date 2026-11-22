// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Pure command result; the executable alone writes stdout and exits.
public struct CLIResult: Sendable, Equatable {
    public let exitCode: Int32
    public let output: String
    public init(exitCode: Int32, output: String) {
        self.exitCode = exitCode; self.output = output
    }
}

/// The terminal seen by `wgex uninstall`: whether a person can answer, and asking the question. Tests inject both.
public struct CLIConsole: Sendable {
    public let isInteractive: Bool
    public let confirm: @Sendable (String) -> Bool
    public init(isInteractive: Bool, confirm: @escaping @Sendable (String) -> Bool) {
        self.isInteractive = isInteractive; self.confirm = confirm
    }

    /// Standard input and output; an answer of `y` or `yes` (any case) confirms, anything else declines.
    public static let standard = CLIConsole(isInteractive: isatty(STDIN_FILENO) != 0 && isatty(STDOUT_FILENO) != 0) { question in
        ask(question, write: { FileHandle.standardError.write(Data($0.utf8)) }, read: { readLine(strippingNewline: true) })
    }

    /// The prompt goes to the `write` sink (standard error in production) so standard output stays a clean result.
    public static func ask(_ question: String, write: (String) -> Void, read: () -> String?) -> Bool {
        write(question + " [y/N] ")
        let answer = read()?.trimmingCharacters(in: .whitespaces).lowercased()
        return answer == "y" || answer == "yes"
    }
}

/// CLI commands share the app's client, but never receive a SecretStore.
public struct WGEXCLICore: Sendable {
    private let client: DaemonClient
    private let service: any ServiceControlling
    private let identifiers: BuildIdentifiers

    private let plistExists: @Sendable () -> Bool
    private let grant: @Sendable () async throws -> any SecureInstallGrant
    private let console: CLIConsole

    public init(
        client: DaemonClient,
        service: any ServiceControlling,
        identifiers: BuildIdentifiers = .current,
        plistExists: @escaping @Sendable () -> Bool = { ServiceController.bundledPlistExists() },
        grant: @escaping @Sendable () async throws -> any SecureInstallGrant = { try await SystemSecureInstallAuthorisation.grant() },
        console: CLIConsole = .standard,
    ) {
        self.grant = grant
        self.console = console
        self.client = client
        self.service = service
        self.identifiers = identifiers
        self.plistExists = plistExists
    }

    public func run(_ arguments: [String]) async -> CLIResult {
        let json = arguments.contains("--json")
        let args = arguments.filter { $0 != "--json" }
        guard let command = args.first else { return usage(json: json) }
        do {
            switch command {
            case "status" where args.count == 1:
                return try await renderStatus(observe(), json: json)
            case "doctor" where args.count == 1:
                return await doctor(json: json)
            case "cutover": return try await cutover(args, json: json)
            case "up" where args.count == 2: return try await up(args[1], json: json)
            case "uninstall": return await uninstall(Array(args.dropFirst()), json: json)
            case "boot-intent": return try await bootIntent(args, json: json)
            case "down", "on-demand": return try await command == "down" ? down(args, json: json) : onDemand(args, json: json)
            default: return usage(json: json)
            }
        } catch {
            return await failure(error, json: json, includeCutoverRecovery: command == "cutover")
        }
    }

    private func up(_ argument: String, json: Bool) async throws -> CLIResult {
        guard let id = UUID(uuidString: argument) else { return usage(json: json) }
        // No Keychain in the CLI. The daemon may use stored secrets or ask the running app.
        _ = try await client.request(.startIntent(profileID: id, transport: nil, hasSecrets: false))
        return render(["result": "started"], json: json, text: "started\n")
    }

    /// `wgex on-demand <UUID> on|off`; no Keychain in the CLI: arming uses daemon-stored secrets or the app's handoff.
    private func onDemand(_ args: [String], json: Bool) async throws -> CLIResult {
        guard args.count == 3, let id = UUID(uuidString: args[1]), ["on", "off"].contains(args[2]) else { return usage(json: json) }
        let arm = args[2] == "on"
        try await arm ? client.armOnDemand(id) : client.disarmOnDemand(id)
        let result = arm ? "armed" : "disarmed"
        return render(["result": result], json: json, text: result + "\n")
    }

    private func down(_ args: [String], json: Bool) async throws -> CLIResult {
        let request: Request
        if args.count == 1 {
            request = .stopCurrent(reason: .userRequested)
        } else if args.count == 2, let id = UUID(uuidString: args[1]) {
            request = .stop(profileID: id, reason: .userRequested)
        } else {
            return usage(json: json)
        }
        do {
            guard case .ok = try await client.request(request) else { throw DaemonError.malformedMessage }
        } catch let error as DaemonError {
            switch error {
            case .tunnel(.backendUnavailable):
                // Intent removal can succeed before teardown fails. Retain the measured failure and its distinct exit.
                guard let telemetry = try? await observe(),
                      telemetry.status.activeProfileID == nil, !telemetry.status.operationInFlight
                else { throw error }
                return renderStatus(telemetry, json: json, stopped: true)
            case .protectionUnknown:
                guard let telemetry = try? await observe() else { throw error }
                return renderStatus(telemetry, json: json, errorName: "protectionUnknown", code: 12)
            default: throw error
            }
        }
        if let telemetry = try? await observe() {
            return renderStatus(telemetry, json: json, stopped: true)
        }
        return render(
            ["result": "stopAccepted", "statusAvailable": false],
            json: json,
            text: "stop accepted (status unavailable)\n",
            code: 12,
        )
    }

    private func renderStatus(
        _ telemetry: StatusTelemetry, json: Bool, stopped: Bool = false, errorName: String? = nil, code: Int32 = 0,
        includeCutoverRecovery: Bool = false,
    ) -> CLIResult {
        let status = telemetry.status
        var fields = Self.statusFields(telemetry)
        let teardownIncomplete = stopped && status.phase != .idle
        fields["result"] = stopped ? (teardownIncomplete ? "stopAccepted" : "stopped") : nil
        fields["error"] = errorName
        let prefix = if let errorName {
            errorName + ": "
        } else if stopped {
            teardownIncomplete ? "stop accepted: " : "stopped: "
        } else {
            ""
        }
        var text = Self.statusText(status, prefix: prefix, uninstall: telemetry.uninstall)
        if status.cutover != nil || includeCutoverRecovery {
            let cutover = Self.cutoverFields(status.cutover)
            text += "cutover: \(cutover["state"] as? String ?? "none")"
            if let deadline = cutover["deadline"] as? String {
                text += "; confirm by \(deadline) (awake time; sleep pauses the timer)"
            }
            if let reason = cutover["reason"] as? String {
                text += "; \(reason)"
            }
            text += "\n"
        }
        if includeCutoverRecovery {
            text += cutoverRecovery
        }
        return render(
            fields, json: json, text: text,
            code: teardownIncomplete ? 18 : code,
        )
    }

    private static func statusText(_ status: TunnelStatus, prefix: String, uninstall: UninstallProgress?) -> String {
        var text = "\(prefix)\(phase(status.phase)) (\(protection(status.protection)))\n"
        if let note = protectionNote(status.protectionNote) {
            text += "protectionNote: " + note + "\n"
        }
        if let onDemand = status.onDemand, onDemand.armedProfileID != nil || onDemand.activated {
            text += onDemandText(onDemand)
        }
        return text + (uninstall.map(uninstallText) ?? "")
    }

    private func doctor(json: Bool) async -> CLIResult {
        let serviceState: String
        if plistExists() {
            var state = service.state.makeAsyncIterator()
            serviceState = await (state.next() ?? .notFound).rawValue
        } else {
            serviceState = "unavailable (query from the app; the CLI runs outside the app bundle)"
        }
        let reachable = await (try? client.connect()) != nil
        let secureInstall: String = if reachable, let report = try? await client.secureInstallStatus() {
            switch report.state {
            case .verified: "verified"
            case .inProgress: "inProgress"
            case let .needsAttention(reason): "needsAttention(\(reason.rawValue))"
            }
        } else {
            reachable ? "unavailable" : "unknown"
        }
        var fields: [String: Any] = [
            "app": identifiers.app, "cli": identifiers.cli, "daemon": identifiers.daemonService,
            "daemonReachable": reachable, "serviceState": serviceState,
            "secureInstall": secureInstall,
        ]
        fields["error"] = reachable ? nil : "daemonUnavailable"
        let text = (reachable ? "" : "daemonUnavailable\n") + "app: \(identifiers.app)\ncli: \(identifiers.cli)\ndaemon: \(identifiers.daemonService)\n"
            + "daemonReachable: \(reachable)\nserviceState: \(serviceState)\nsecureInstall: \(secureInstall)\n"
        return render(fields, json: json, text: text, code: reachable ? 0 : 1)
    }

    private func failure(_ error: any Error, json: Bool, includeCutoverRecovery: Bool = false) async -> CLIResult {
        let category = CLIErrorCategory.resolve(error)
        var fields: [String: Any] = ["error": category.name]
        var text = category.name
        if category.name == "underlayResolverNoAnswer" {
            let message = "No answer from the underlay resolver; check the network connection and retry."
            fields["message"] = message; text += ": " + message
        }
        if (error as? DaemonError) == .recovering, case let .status(status) = try? await client.request(.status) {
            fields["protection"] = Self.protection(status.protection)
            text += ": protection=" + Self.protection(status.protection)
        }
        if category.code == 3 {
            let instruction: String
            if category.name == "secretsHandoffDisconnected" {
                let command = includeCutoverRecovery ? "cutover start" : "up"
                instruction = "app went away during the secrets handoff; open WGEX and keep it running with this profile imported; "
                    + "leave the tunnel disconnected, then retry " + command
            } else {
                instruction = includeCutoverRecovery
                    ? "open WGEX and keep it running with this profile imported; leave the tunnel disconnected, then retry cutover start"
                    : "open WGEX to connect"
            }
            if includeCutoverRecovery || category.name == "secretsHandoffDisconnected" {
                fields["instruction"] = instruction
            }
            text += ": " + instruction
        }
        if includeCutoverRecovery, [1, 12].contains(category.code) {
            fields["recovery"] = cutoverRecovery
            text += "\n" + cutoverRecovery
        }
        return render(fields, json: json, text: text + "\n", code: category.code)
    }

    private func usage(json: Bool) -> CLIResult {
        render(
            ["error": "usage"],
            json: json,
            text: "usage: wgex status|doctor|up <profile UUID>|down [profile UUID] [--json]\n"
                + "       wgex on-demand <profile UUID> on|off [--json]\n"
                + "       wgex boot-intent <profile UUID> on|off [--json]\n"
                + "       wgex cutover start <profile UUID> --confirm-within <60s..60m> [--json]\n"
                + "       wgex cutover confirm|abort|status [--json]\n"
                + "       wgex uninstall [--purge] [--yes] [--json]\n"
                + "Exit codes: 0 done; 1 daemon unavailable; 2 usage; 4 authorisation refused;\n"
                + "  10 uninstall declined; 19 uninstall cleanup step failed (names the step; rerun resumes);\n"
                + "  20 uninstall result unknown (rerun)\n"
                + "Secrets for up and cutover start, when absent from the daemon store:\n"
                + "  owner: app secrets handoff; non-owner (including root): unauthorised (exit 4)\n"
                + "  no app: secretsUnavailable (exit 3); silent app: timedOut (exit 8)\n",
            code: 2,
        )
    }

    private func render(_ fields: [String: Any], json: Bool, text: String, code: Int32 = 0) -> CLIResult {
        guard json else { return CLIResult(exitCode: code, output: text) }
        let bytes = (try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data()
        return CLIResult(exitCode: code, output: String(decoding: bytes, as: UTF8.self) + "\n")
    }

    private static func phase(_ phase: TunnelPhase) -> String {
        switch phase {
        case .idle: "idle"
        case .preparing: "preparing"
        case .configuring: "configuring"
        case .active: "active"
        case .reasserting: "reasserting"
        case .captiveWindow: "captiveWindow"
        case .stopping: "stopping"
        case .failed: "failed"
        }
    }

    private static func protection(_ protection: ProtectionState) -> String {
        switch protection {
        case .protected: "protected"
        case .blocked: "blocked"
        case .unprotected: "unprotected"
        case .unknown: "unknown"
        case .unsupported: "unsupported"
        case .captiveWindow: "captiveWindow"
        }
    }
}

/// Fixed CLI categories; never formats arbitrary server or system descriptions.
private enum CLIErrorCategory {
    static func resolve(_ error: any Error) -> (name: String, code: Int32) {
        let row: DaemonFailurePresentation? = if let daemon = error as? DaemonError {
            daemon.presentation
        } else if let tunnel = error as? TunnelError {
            DaemonError.tunnel(tunnel).presentation
        } else if let failure = error as? DaemonFailure {
            DaemonFailure.catalog[failure.kind]
        } else {
            nil
        }
        return (row?.cliName ?? "system", row?.cliExitCode ?? 16)
    }
}

extension WGEXCLICore {
    /// The app's wording for refusing start before login (`MacStrings.startingBeforeLoginRequires`).
    private static let bootRefusal = "Starting before login requires secure install and storing the key with the background service."

    /// `wgex boot-intent <UUID> on|off`: the app's start-before-login request through `WGEXDaemonClient`, with the daemon's own
    /// checks (secure install and a daemon-stored key). The CLI holds no Keychain and sends no secrets, so it refuses like the
    /// app does when either is missing. The commit is the daemon's own, so on-demand's DEC-012 rules apply to it unchanged.
    private func bootIntent(_ args: [String], json: Bool) async throws -> CLIResult {
        guard args.count == 3, let id = UUID(uuidString: args[1]), ["on", "off"].contains(args[2]) else { return usage(json: json) }
        let enabled = args[2] == "on"
        do {
            try await client.setStartBeforeLogin(id, enabled: enabled)
        } catch let error as DaemonError where enabled && [.secureInstallRequired, .secretsUnavailable].contains(error) {
            let category = CLIErrorCategory.resolve(error)
            return render(
                ["error": category.name, "message": Self.bootRefusal], json: json,
                text: category.name + ": " + Self.bootRefusal + "\n", code: category.code,
            )
        }
        let result = enabled ? "bootIntentOn" : "bootIntentOff"
        return render(["result": result], json: json, text: result + "\n")
    }

    private func cutover(_ args: [String], json: Bool) async throws -> CLIResult {
        guard args.count >= 2 else { return usage(json: json) }
        switch args[1] {
        case "start" where args.count == 5 && args[3] == "--confirm-within":
            guard let id = UUID(uuidString: args[2]), let seconds = Self.cutoverSeconds(args[4]) else { return usage(json: json) }
            _ = try await client.startCutover(id, confirmWithin: seconds)
        case "confirm" where args.count == 2: try await client.confirmCutover()
        case "abort" where args.count == 2: try await client.abortCutover()
        case "status" where args.count == 2: break
        default: return usage(json: json)
        }
        return try await renderStatus(observe(), json: json, includeCutoverRecovery: !json)
    }

    /// Attempts a status read may take while startup restores the policy: the daemon holds each one up to 3 s, then answers
    /// `recovering`, so the CLI reaches the run's first publication (DEC-011) or reports recovery within about 12 s.
    private static let startupAttempts = 4

    /// The status with its telemetry, read again while the daemon answers `recovering` at startup.
    private func observe() async throws -> StatusTelemetry {
        var attempt = 1
        while true {
            do { return try await client.statusTelemetry() } catch DaemonError.recovering where attempt < Self.startupAttempts {
                attempt += 1
            }
        }
    }

    /// Every field of `wgex status --json`; the old fields keep their meaning and the telemetry sits beside them (M03-T01).
    /// `startup` holds the run's first publication in the same fields, or null before it exists and from an older daemon
    /// (DEC-018).
    private static func statusFields(_ telemetry: StatusTelemetry) -> [String: Any] {
        var fields = publicationFields(telemetry.current)
        fields["startup"] = telemetry.startup.map(publicationFields) ?? NSNull() as Any
        return fields
    }

    /// The fields of one status publication.
    private static func publicationFields(_ publication: StatusPublication) -> [String: Any] {
        let status = publication.status
        var fields: [String: Any] = ["phase": Self.phase(status.phase), "protection": Self.protection(status.protection)]
        fields["protectionNote"] = Self.protectionNote(status.protectionNote) ?? NSNull() as Any
        fields["sequence"] = status.sequence
        fields["activeProfileID"] = status.activeProfileID?.uuidString ?? NSNull() as Any
        fields["measuredAt"] = status.measuredAt.map { ISO8601DateFormatter().string(from: $0) } ?? NSNull() as Any
        fields["measuredAtContinuous"] = status.measuredAtContinuous ?? NSNull() as Any
        fields["operationInFlight"] = status.operationInFlight
        fields["policyEnforcing"] = status.policyEnforcing
        fields["cutover"] = Self.cutoverFields(status.cutover)
        fields["cutoverRollbackFailures"] = status.cutoverRollbackFailures
        fields["verifiedAt"] = status.verifiedAt.map { ISO8601DateFormatter().string(from: $0) } ?? NSNull() as Any
        fields["verifiedAtContinuous"] = status.verifiedAtContinuous ?? NSNull() as Any
        fields["onDemand"] = Self.onDemandFields(status.onDemand)
        fields["uninstall"] = publication.uninstall.map { progress in
            [
                "completed": progress.completed, "purgeState": progress.purgeState,
                "pendingStep": progress.pendingStep?.rawValue ?? NSNull() as Any,
            ] as [String: Any]
        } ?? NSNull() as Any
        if let reason = status.recoveryFailureReason {
            fields["recoveryFailureReason"] = reason.rawValue
        }
        fields.merge(telemetryFields(publication)) { $1 }
        return fields
    }

    /// The M03-T01 telemetry beside the status fields: the journal policy and, in Lab builds only, the owner pf reference.
    private static func telemetryFields(_ publication: StatusPublication) -> [String: Any] {
        var fields: [String: Any] = ["journalPolicy": publication.journalPolicy?.rawValue ?? NSNull() as Any]
        #if WGEX_LAB_BUILD
            fields["ownerPFToken"] = publication.ownerPFToken ?? NSNull() as Any
        #endif
        return fields
    }

    private static func cutoverSeconds(_ input: String) -> Int? {
        guard let unit = input.last, let value = Int(input.dropLast()), value > 0,
              let multiplier = ["s": 1, "m": 60][String(unit)] else { return nil }
        let (seconds, overflow) = value.multipliedReportingOverflow(by: multiplier)
        return !overflow && (60 ... 3600).contains(seconds) ? seconds : nil
    }

    private static func protectionNote(_ note: ProtectionNote?) -> String? {
        switch note {
        case .ipv6Unavailable: "ipv6Unavailable"
        case .dnsUnverified: "dnsUnverified"
        case .verificationFailed: "verificationFailed"
        case .canaryFailed: "canaryFailed"
        case nil: nil
        }
    }

    /// ADR-030 status fields; the SSID itself is never part of status.
    private static func onDemandFields(_ status: OnDemandStatus?) -> Any {
        guard let status else { return NSNull() }
        var fields: [String: Any] = [
            "armedProfileID": status.armedProfileID?.uuidString ?? NSNull() as Any,
            "activated": status.activated,
            "network": status.network.rawValue,
            "evaluatedAtContinuous": status.evaluatedAtContinuous ?? NSNull() as Any,
        ]
        switch status.ssid {
        case .notRequired: fields["ssid"] = ["state": "notRequired"]
        case .known: fields["ssid"] = ["state": "known"]
        case .settling: fields["ssid"] = ["state": "settling"]
        case let .unavailable(reason): fields["ssid"] = ["state": "unavailable", "reason": reason.rawValue]
        }
        switch status.decision {
        case .connect: fields["decision"] = ["state": "connect"]
        case .disconnect: fields["decision"] = ["state": "disconnect"]
        case let .hold(reason): fields["decision"] = ["state": "hold", "reason": reason.rawValue]
        case let .paused(reason): fields["decision"] = ["state": "paused", "reason": reason.rawValue]
        case nil: fields["decision"] = NSNull()
        }
        return fields
    }

    /// The uninstall the daemon holds (M05-T14): completed, or in progress with the step still owed.
    private static func uninstallText(_ uninstall: UninstallProgress) -> String {
        let purge = uninstall.purgeState ? " (purge)" : ""
        guard !uninstall.completed else { return "uninstall: completed\(purge); the service is uninstalled; \(uninstallNext)\n" }
        let step = uninstall.pendingStep.map { "; step \($0.rawValue) pending" } ?? ""
        return "uninstall: in progress\(purge)\(step); run wgex uninstall again to resume\n"
    }

    private static func onDemandText(_ status: OnDemandStatus) -> String {
        var text = "onDemand: " + (status.armedProfileID.map { "armed \($0.uuidString)" } ?? "disarmed")
        text += status.activated ? "; activated" : ""
        text += "; network " + status.network.rawValue
        switch status.decision {
        case .connect: text += "; connect"
        case .disconnect: text += "; disconnect"
        case let .hold(reason): text += "; hold (" + reason.rawValue + ")"
        case let .paused(reason): text += "; paused (" + reason.rawValue + ")"
        case nil: break
        }
        if case let .unavailable(reason) = status.ssid {
            text += "; SSID unavailable (" + reason.rawValue + ")"
        }
        return text + "\n"
    }

    private static func cutoverFields(_ state: CutoverState?) -> [String: Any] {
        switch state {
        case let .armed(deadline): ["state": "armed", "deadline": ISO8601DateFormatter().string(from: deadline)]
        case .confirmed: ["state": "confirmed"]
        case let .rolledBack(reason): ["state": "rolledBack", "reason": reason.rawValue]
        case nil: ["state": "none"]
        }
    }

    private var cutoverRecovery: String {
        let cli = "/Applications/WGEX.app/Contents/Helpers/wgex"
        return """
        Confirm: \(cli) cutover confirm
        Recover: \(cli) cutover abort
        If the daemon is unreachable, use the saved M1-12 RUNBOOK. Boot out first; clean shutdown may replace the token:
        sudo /bin/launchctl bootout system/\(identifiers.daemonService)
        journal='/Library/Application Support/WGEX/journal.json'
        profile=$(sudo /usr/bin/plutil -extract cutover.profileID raw -o - "$journal")
        recorded_boot=$(sudo /usr/bin/plutil -extract pfBootSession raw -o - "$journal")
        recorded_pid=$(sudo /usr/bin/plutil -extract pfTokenPID raw -o - "$journal")
        token=$(sudo /usr/bin/plutil -extract pfToken raw -o - "$journal")
        sudo /sbin/pfctl -a com.apple/wgex -F all
        # Only release a token matching the journal boot UUID, PID and current References row:
        sudo /sbin/pfctl -X "$token"
        # Only delete routes whose interface and RTF_PROTO2 ownership match the journal:
        wgex_utun='<journalled-utun-name>'
        sudo /sbin/route -n delete -net 0.0.0.0/1 -interface "$wgex_utun"
        sudo /sbin/route -n delete -net 128.0.0.0/1 -interface "$wgex_utun"
        # Only if these IPv6 routes are journalled and still owned by that interface:
        sudo /sbin/route -n delete -inet6 -net ::/1 -interface "$wgex_utun"
        sudo /sbin/route -n delete -inet6 -net 8000::/1 -interface "$wgex_utun"
        printf 'remove State:/Network/Service/%s/DNS\\nquit\\n' "$profile" | sudo /usr/sbin/scutil

        """
    }
}

public extension DaemonClient {
    /// Starts a bounded trial through the same handshake and separate secret argument as ordinary start.
    @discardableResult
    func startCutover(_ id: UUID, confirmWithin seconds: Int) async throws -> Generation {
        let hello = try await connect()
        guard hello.daemonBuild == clientBuild else { throw DaemonError.disconnected }
        var secrets = try await secretData(id)
        defer { secrets.resetBytes(in: 0 ..< secrets.count) }
        guard case let .started(generation) = try await exchange(
            .startCutover(profileID: id, confirmWithin: seconds, hasSecrets: !secrets.isEmpty),
            secrets: secrets.isEmpty ? nil : secrets,
        ) else { throw DaemonError.malformedMessage }
        lastGeneration = generation
        return generation
    }

    /// Confirms the current trial; only its owner at the console may commit it.
    func confirmCutover() async throws {
        guard case .ok = try await request(.confirmCutover) else { throw DaemonError.malformedMessage }
    }

    /// Requests best-effort local rollback, including during daemon recovery.
    func abortCutover() async throws {
        guard case .ok = try await request(.abortCutover) else { throw DaemonError.malformedMessage }
    }
}

extension WGEXCLICore {
    private static let uninstallQuestion = "Uninstall WGEX? This stops the tunnel and turns the kill switch off"
    private static let uninstallNext = "open WGEX to finish removing the background service and login item"

    /// `wgex uninstall [--purge] [--yes]`: confirms, takes the admin right (M05-T07), then runs the daemon's uninstall. Nothing
    /// reaches the daemon, and no admin prompt appears, before the confirmation. `--purge` removes the daemon's own state only;
    /// the app's profiles and keychain items stay.
    private func uninstall(_ flags: [String], json: Bool) async -> CLIResult {
        let allowed: Set = ["--purge", "--yes"]
        guard Set(flags).isSubset(of: allowed), Set(flags).count == flags.count else { return usage(json: json) }
        let purge = flags.contains("--purge")
        if !flags.contains("--yes") {
            guard console.isInteractive else { return usage(json: json) }
            guard console.confirm(Self.uninstallQuestion) else {
                return render(["error": "declined"], json: json, text: "declined: nothing changed\n", code: 10)
            }
        }
        let held: any SecureInstallGrant
        do { held = try await grant() } catch {
            return uninstallFailure(name: "unauthorised", code: 4, json: json, text: "unauthorised: admin approval was not given\n")
        }
        do {
            guard await (try? client.connect()) != nil else {
                return uninstallFailure(name: "daemonUnavailable", code: 1, json: json, text: "daemonUnavailable: open WGEX to connect\n")
            }
            try await client.uninstall(purgeState: purge, authorization: held.externalForm)
        } catch let DaemonError.uninstallFailed(step) {
            return uninstallFailure(
                name: "uninstallFailed", code: 19, json: json,
                text: "uninstallFailed: step \(step.rawValue); run wgex uninstall again to resume\n",
                extra: ["step": step.rawValue],
            )
        } catch DaemonError.notAuthorised, DaemonError.unauthorised, DaemonError.secureInstallRequired {
            return uninstallFailure(name: "unauthorised", code: 4, json: json, text: "unauthorised: the daemon refused the request\n")
        } catch DaemonError.disconnected, TunnelError.timedOut {
            return uninstallFailure(
                name: "resultUnknown", code: 20, json: json,
                text: "resultUnknown: the daemon did not answer; run wgex uninstall again to find out\n",
            )
        } catch {
            let category = CLIErrorCategory.resolve(error)
            return uninstallFailure(name: category.name, code: category.code, json: json, text: category.name + "\n")
        }
        withExtendedLifetime(held) {}
        return render(
            ["result": "uninstalled", "purge": purge, "next": Self.uninstallNext], json: json,
            text: "uninstalled\n" + Self.uninstallNext + "\n",
        )
    }

    private func uninstallFailure(
        name: String, code: Int32, json: Bool, text: String, extra: [String: Any] = [:],
    ) -> CLIResult {
        render(["error": name].merging(extra) { $1 }, json: json, text: text, code: code)
    }
}
