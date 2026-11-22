// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// Session-only, bounded measurements behind the live rates; no disk history and no invented samples.
    public struct MacSessionTraffic {
        private struct Sample {
            let date: Date
            let received: Double
            let sent: Double
        }

        private var samples: [Sample] = []
        private var previous: TunnelStatistics?
        private var rate: Rates?
        public private(set) var startedAt: Date?
        /// Expected statistics cadence; longer gaps have no measured delta.
        public static let samplingInterval: TimeInterval = 2
        public init() {}

        /// A rate belongs to one pair of measured samples, never the service's placeholder rate.
        public struct Rates: Equatable {
            public let generation: UInt64
            public let sampledAt: Date
            public let download: Double
            public let upload: Double
        }

        /// Missing, future or old samples cannot be described as a live rate.
        public func rates(at date: Date, generation: UInt64) -> Rates? {
            guard let rate, rate.generation == generation,
                  date >= rate.sampledAt,
                  date.timeIntervalSince(rate.sampledAt) <= Self.samplingInterval * 2.5 else { return nil }
            return rate
        }

        /// Records an observed transition to active; sample arrival never defines session age.
        public mutating func startSession(at date: Date?) {
            startedAt = date
        }

        public var hasMeasurements: Bool {
            !samples.isEmpty
        }

        /// A replayed sample cannot restore counters after a failed request or replace newer totals.
        package func accepts(_ value: TunnelStatistics) -> Bool {
            guard let previous, previous.generation == value.generation else { return true }
            return value.sampledAt > previous.sampledAt
        }

        public mutating func append(_ value: TunnelStatistics) {
            guard !value.peers.isEmpty else { rate = nil; previous = nil; return }
            guard accepts(value) else { return }
            rate = nil
            guard let previous, previous.generation == value.generation else {
                samples = []; previous = value; return
            }
            defer { self.previous = value }
            guard value.sampledAt.timeIntervalSince(previous.sampledAt) <= Self.samplingInterval * 2.5 else { return }
            guard let delta = deltas(from: previous, to: value) else { samples = []; return }
            let interval = value.sampledAt.timeIntervalSince(previous.sampledAt)
            rate = Rates(
                generation: value.generation,
                sampledAt: value.sampledAt,
                download: delta.received / interval,
                upload: delta.sent / interval,
            )
            samples.append(Sample(date: value.sampledAt, received: delta.received, sent: delta.sent))
            if samples.count > 1800 {
                samples.removeFirst(samples.count - 1800)
            }
        }

        private func deltas(from old: TunnelStatistics, to new: TunnelStatistics) -> (received: Double, sent: Double)? {
            let oldKeys = Set(old.peers.map(\.publicKey))
            guard oldKeys.count == old.peers.count, new.peers.count == old.peers.count,
                  Set(new.peers.map(\.publicKey)) == oldKeys else { return nil }
            var received = 0.0
            var sent = 0.0
            for peer in new.peers {
                guard let previous = old.peers.first(where: { $0.publicKey == peer.publicKey }),
                      peer.rxBytes >= previous.rxBytes, peer.txBytes >= previous.txBytes else { return nil }
                received += Double(peer.rxBytes - previous.rxBytes)
                sent += Double(peer.txBytes - previous.txBytes)
            }
            return (received, sent)
        }
    }
#endif
