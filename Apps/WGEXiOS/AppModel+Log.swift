// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import Observation
import WGEXCore
import WGEXDiagnostics

@MainActor @Observable
internal final class IOSLogState {
    internal var text = ""
    @ObservationIgnored internal let file: SharedLogFile
    @ObservationIgnored internal var refreshInterval: Duration = .seconds(1)

    internal init(file: SharedLogFile) {
        self.file = file
    }
}

internal extension AppModel {
    var logText: String {
        log.text
    }

    /// The view owns this task. Closing it cancels polling; reopening reads the persisted log immediately.
    func watchLog() async {
        let stamp = Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt)
        while !Task.isCancelled {
            let entries = log.file.read()
            log.text = entries.map {
                "\($0.date.formatted(stamp)) [\($0.process.rawValue)] \($0.message)"
            }.joined(separator: "\n")
            do { try await Task.sleep(for: log.refreshInterval) }
            catch { break }
        }
    }

    /// Reads a fresh snapshot, including lines written since the view's last refresh.
    func exportLog() -> Data {
        log.file.export()
    }

    enum LogLifecycle: String {
        case started = "App session started"
        case stopped = "App session ended"
    }

    func logLifecycle(_ event: LogLifecycle) {
        log.file.append(event.rawValue, process: .app)
    }

    /// Only fixed phase names cross this boundary, never profile names, configuration or error descriptions.
    func logPhase(_ phase: TunnelPhase) {
        let message = switch phase {
        case .idle: "Tunnel idle"
        case .preparing: "Tunnel preparing"
        case .configuring: "Tunnel configuring"
        case .active: "Tunnel active"
        case .reasserting: "Tunnel reasserting"
        case .stopping: "Tunnel stopping"
        case .captiveWindow: "Tunnel captive window"
        case .failed: "Tunnel failed"
        }
        log.file.append(message, process: .app)
    }
}
