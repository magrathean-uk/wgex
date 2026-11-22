// SPDX-License-Identifier: MIT

import Foundation
import Observation
import WGEXCore
import WGEXTesting
import WGEXUI

/// A deterministic status stream for animated previews: a
/// ``WGEXTesting/FakeTunnelBackend`` plays a scripted connection on a
/// ``WGEXTesting/FakeClock``, and each ``tick()`` moves fake time on by one
/// second. Previews tick on a real timer; tests tick by hand.
@Observable
public final class OrbPreviewScenario {
    /// Generation used by the script.
    public static let generation = Generation(rawValue: 1)

    /// One cycle: connect, protected, path change, protected, failure with
    /// the kill switch blocking, then disconnected. Delays are fake seconds.
    public static let script: [FakeTunnelBackend.Step] = [
        .init(phase: .preparing(generation), protection: .blocked, delay: .seconds(1)),
        .init(phase: .configuring(generation), protection: .blocked, delay: .seconds(1)),
        .init(phase: .active(generation), protection: .protected, delay: .seconds(1)),
        .init(phase: .reasserting(generation, reason: .pathChanged), protection: .blocked, delay: .seconds(4)),
        .init(phase: .active(generation), protection: .protected, delay: .seconds(1)),
        .init(phase: .failed(.timedOut, blockedByPolicy: true, needsSecrets: false), protection: .blocked, delay: .seconds(4)),
        .init(phase: .idle, protection: .unprotected, delay: .seconds(2)),
    ]

    /// Latest status from the stream.
    public private(set) var status: TunnelStatus = .idle
    /// Verdict of every status received, in order.
    public private(set) var history: [ProtectionVerdict] = []

    /// The fake clock driving the script.
    @ObservationIgnored public let clock = FakeClock()
    /// The fake backend playing the script.
    @ObservationIgnored public let backend: FakeTunnelBackend
    @ObservationIgnored private var tasks: [Task<Void, Never>] = []

    /// Creates an idle scenario.
    public init() {
        backend = FakeTunnelBackend(clock: clock)
        backend.scriptStart(Self.script)
    }

    /// Presentation of the latest status at the fixed preview time.
    public var presentation: ProtectionPresentation {
        ProtectionPresentation(status: status, context: ProtectionContext(platform: .mac, now: PreviewFixtures.referenceDate))
    }

    /// Subscribes to the backend and starts replaying the script in a loop.
    public func begin() async {
        guard tasks.isEmpty else { return }
        try? await backend.install(PreviewFixtures.profile)
        let stream = backend.statusUpdates()
        tasks.append(Task { [weak self] in
            for await status in stream {
                self?.receive(status)
            }
        })
        let backend = backend
        tasks.append(Task {
            while !Task.isCancelled {
                do {
                    try await backend.start(PreviewFixtures.profile.id, transport: nil)
                } catch {
                    return
                }
            }
        })
    }

    /// Moves fake time on by one second.
    public func tick() {
        clock.advance(by: .seconds(1))
    }

    /// Ticks once per `interval` of real time until cancelled (previews).
    public func run(interval: Duration = .milliseconds(1500)) async {
        await begin()
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: interval)
            } catch {
                break
            }
            tick()
        }
        cancel()
    }

    /// Stops listening and replaying.
    public func cancel() {
        tasks.forEach { $0.cancel() }
        tasks = []
    }

    private func receive(_ status: TunnelStatus) {
        self.status = status
        history.append(presentation.verdict)
    }
}
