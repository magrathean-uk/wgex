// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Event history controls, transition descriptions and redacted error copy.
public nonisolated extension MacStrings {
    /// Copy used in the Mac events list and toast.
    static let paused = "Paused"
    /// Copy used in the Mac events list and toast.
    static let live = "Live"
    /// Copy used in the Mac events list and toast.
    static let eventsFormat = "Events format"
    /// Copy used in the Mac events list and toast.
    static let timeline = "Timeline"
    /// Copy used in the Mac events list and toast.
    static let rawLog = "Log"
    /// Copy used in the Mac events list and toast.
    static let rawLogsAreNotAvailableFromThis = "The log is not available from this backend. Keys and configuration text are never shown here."
    /// Log view placeholder before the first line arrives.
    static let noLogLinesYet = "No log lines yet."
    /// Log view button that writes the log to a chosen .txt file.
    static let saveLog = "Save Log…"
    /// Shown when the chosen log file could not be written.
    static let theLogCouldNotBeSaved = "The log could not be saved."
    /// Default file name in the log save panel.
    static func logFilename(_ stamp: String) -> String {
        "WGEX Log \(stamp).txt"
    }

    /// Copy used in the event description presenter.
    static let statusChanged = "Status changed"
    /// Copy used in the event description presenter.
    static let handshakeCompleted = "Handshake completed"
    /// Copy used in the event description presenter.
    static let noReplyFromThePeer = "No reply from the peer"
    /// Copy used in the event description presenter.
    static let peerEndpointChanged = "Peer endpoint changed"
    /// Copy used in the event description presenter.
    static let transportChanged = "Transport changed"
    /// Copy used in the event description presenter.
    static let networkChangedReconnecting = "Network changed, reconnecting"
    /// Copy used in the event description presenter.
    static let connectionFailed = "Activation failed: "
    /// Copy used in the event description presenter.
    static let captiveWindowOpened = "Sign-in window opened"
    /// Copy used in the event description presenter.
    static let killSwitchNotAvailableOnThis = "Kill switch not available on this device"
    /// Copy used in the event description presenter.
    static let anotherTunnelIsConnected = "another tunnel is active"
    /// Copy used in the event description presenter.
    static let tunnelNotFound = "tunnel not found"
    /// Copy used in the event description presenter.
    static let theConfigurationIsInvalid = "the configuration is invalid"
    /// Copy used in the event description presenter.
    static let keysAreUnavailable = "keys are unavailable"
    /// Copy used in the event description presenter.
    static let backgroundServiceUnavailable = "background service unavailable"
    /// Copy used in the event description presenter.
    static let permissionDenied = "permission denied"
    /// Copy used in the event description presenter.
    static let timedOut = "timed out"
    /// Names a public engine error code, without its payload.
    static func engineError(_ code: String) -> String {
        "engine error \(code)"
    }

    /// Shares the Core events label with other platforms.
    static let events = UserStrings.events
    /// Copy used in the shared events timeline.
    static let noEventsYet = "No events yet"
}
