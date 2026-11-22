// SPDX-License-Identifier: MIT

import Foundation
import Observation

/// UI boundary only. The app adapter uses WGEXPairing; WGEXUI has no protocol/transport dependency.
public struct TVPairingSnapshot: Sendable, Equatable {
    public enum Stage: Sendable { case waiting, confirmSAS, receiving, overwrite, completed, failed, expired, exhausted, stopped }
    public var payload: String
    public var stage: Stage
    public var sas: String?
    public var attempts: Int
    public init(payload: String = "", stage: Stage = .waiting, sas: String? = nil, attempts: Int = 0) {
        self.payload = payload; self.stage = stage; self.sas = sas; self.attempts = attempts
    }
}

@MainActor
public protocol TVPairingReceiving: AnyObject {
    func start() async throws -> TVPairingSnapshot
    func snapshot() async -> TVPairingSnapshot
    func confirmSAS(_ sas: String, accepted: Bool) async throws
    func confirmOverwrite(_ accepted: Bool) async
    func stop() async
}

@MainActor @Observable
public final class TVPairingModel {
    public private(set) var snapshot = TVPairingSnapshot()
    public private(set) var secondsRemaining = 120
    public private(set) var isBusy = false
    @ObservationIgnored private let receiver: any TVPairingReceiving
    @ObservationIgnored private let now: @MainActor () -> Duration
    @ObservationIgnored private var deadline: Duration = .zero
    @ObservationIgnored private var revision = 0

    public init(receiver: any TVPairingReceiving, now: @escaping @MainActor () -> Duration = TVPairingModel.monotonicNow) {
        self.receiver = receiver; self.now = now
    }

    public static func monotonicNow() -> Duration {
        .seconds(ProcessInfo.processInfo.systemUptime)
    }

    public var canConfirm: Bool {
        snapshot.stage == .confirmSAS && now() < deadline && secondsRemaining > 0 && snapshot.attempts <= 3 &&
            snapshot.sas?.count == 6 && snapshot.sas?.utf8.allSatisfy { (48 ... 57).contains($0) } == true && !isBusy
    }

    public var countdown: String {
        String(format: "%d:%02d", secondsRemaining / 60, secondsRemaining % 60)
    }

    public func newCode() async {
        guard !isBusy else { return }
        revision += 1; let current = revision
        isBusy = true
        snapshot = TVPairingSnapshot()
        await receiver.stop()
        deadline = now() + .seconds(120); secondsRemaining = 120
        do {
            let started = try await receiver.start()
            guard current == revision else { await receiver.stop(); isBusy = false; return }
            snapshot = started
            if snapshot.stage == .expired {
                secondsRemaining = 0
            }
        } catch {
            if current == revision {
                snapshot = TVPairingSnapshot(stage: .failed)
            }
        }
        isBusy = false
    }

    public func refresh() async {
        guard !isBusy, snapshot.stage != .stopped else { return }
        let current = revision
        let updated = await receiver.snapshot()
        guard current == revision else { return }
        snapshot = updated
        let remaining = deadline - now()
        let components = remaining.components
        secondsRemaining = max(0, min(120, Int(components.seconds) + (components.attoseconds > 0 ? 1 : 0)))
        if snapshot.stage == .completed {
            return
        }
        if secondsRemaining == 0 || snapshot.stage == .expired {
            secondsRemaining = 0
            snapshot.stage = .expired; snapshot.payload = ""; snapshot.sas = nil
            await receiver.stop()
        } else if snapshot.attempts >= 3, snapshot.stage == .failed {
            snapshot.stage = .exhausted
        }
    }

    public func confirm(_ accepted: Bool) async {
        await refresh()
        guard canConfirm, let sas = snapshot.sas else { return }
        isBusy = true
        do { try await receiver.confirmSAS(sas, accepted: accepted) }
        catch { snapshot.stage = .failed }
        isBusy = false
        await refresh()
    }

    public func overwrite(_ accepted: Bool) async {
        await refresh()
        guard snapshot.stage == .overwrite, secondsRemaining > 0 else { return }
        await receiver.confirmOverwrite(accepted)
        await refresh()
    }

    public func stop() async {
        revision += 1
        snapshot = TVPairingSnapshot(stage: .stopped)
        await receiver.stop()
    }
}

/// Scriptable UI fake; it never opens a socket or stores a profile.
@MainActor
public final class TVFakePairingReceiver: TVPairingReceiving {
    public var value: TVPairingSnapshot
    public private(set) var stopped = false
    public private(set) var confirmations: [Bool] = []
    public init(value: TVPairingSnapshot = TVPairingSnapshot()) {
        self.value = value
    }

    public func start() async throws -> TVPairingSnapshot {
        stopped = false
        if value.payload.hasPrefix("wgex-pair://v1/"), let key = value.payload.split(separator: "/").last {
            value.payload = "wgex-pair://v1/\(UUID().uuidString.lowercased())/\(key)"
        }
        return value
    }

    public func snapshot() async -> TVPairingSnapshot {
        value
    }

    public func confirmSAS(_ sas: String, accepted: Bool) async throws {
        guard sas == value.sas else { return }
        confirmations.append(accepted); value.stage = accepted ? .receiving : .failed
    }

    public func confirmOverwrite(_ accepted: Bool) async {
        value.stage = accepted ? .completed : .failed
    }

    public func stop() async {
        stopped = true
    }
}
