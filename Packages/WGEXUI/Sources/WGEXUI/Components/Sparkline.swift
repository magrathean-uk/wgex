// SPDX-License-Identifier: MIT

import SwiftUI

/// Samples over a sliding window, downsampled into buckets for drawing.
public nonisolated struct SparklineSeries: Sendable, Hashable {
    /// One measurement.
    public struct Sample: Sendable, Hashable {
        /// When it was taken.
        public var time: Date
        /// The value.
        public var value: Double

        /// Creates a sample.
        public init(time: Date, value: Double) {
            self.time = time
            self.value = value
        }
    }

    /// Default window: the last 30 seconds.
    public static let defaultWindow: TimeInterval = 30

    /// Window length in seconds.
    public let window: TimeInterval
    /// Samples in time order within the window of the newest one.
    public private(set) var samples: [Sample]

    /// Creates a series.
    public init(window: TimeInterval = defaultWindow, samples: [Sample] = []) {
        self.window = window
        self.samples = []
        for sample in samples {
            append(sample.value, at: sample.time)
        }
    }

    /// Adds a sample in time order and drops samples older than the window.
    /// Non-finite and negative values are ignored.
    public mutating func append(_ value: Double, at time: Date) {
        guard value.isFinite, value >= 0 else { return }
        let index = samples.firstIndex { $0.time > time } ?? samples.endIndex
        samples.insert(Sample(time: time, value: value), at: index)
        if let newest = samples.last?.time {
            samples.removeAll { newest.timeIntervalSince($0.time) > window }
        }
    }

    /// The maximum value per bucket over the window ending at `end`, oldest
    /// first; nil for buckets without samples. Peaks are preserved.
    public func buckets(count: Int, endingAt end: Date) -> [Double?] {
        guard count > 0 else { return [] }
        let start = end.addingTimeInterval(-window)
        var result = [Double?](repeating: nil, count: count)
        for sample in samples where sample.time > start && sample.time <= end {
            let position = sample.time.timeIntervalSince(start) / window
            let index = min(count - 1, max(0, Int((position * Double(count)).rounded(.up)) - 1))
            result[index] = max(result[index] ?? 0, sample.value)
        }
        return result
    }

    /// Buckets scaled to 0...1 by the window's peak; empty buckets are 0.
    public func normalised(count: Int, endingAt end: Date) -> [Double] {
        let values = buckets(count: count, endingAt: end)
        let peak = values.compactMap(\.self).max() ?? 0
        return values.map { value in
            guard let value, peak > 0 else { return 0 }
            return value / peak
        }
    }

    /// The largest value in the window ending at `end`.
    public func peak(endingAt end: Date) -> Double? {
        buckets(count: 1, endingAt: end).first ?? nil
    }
}

/// A 30-second line of a rate, downsampled to the drawing width.
public struct Sparkline: View {
    private let title: String
    private let series: SparklineSeries
    private let now: Date
    private let colour: StateColor
    private let bucketCount: Int

    /// Creates a sparkline ending at `now`.
    public init(title: String, series: SparklineSeries, now: Date, colour: StateColor = .transport, bucketCount: Int = 30) {
        self.title = title
        self.series = series
        self.now = now
        self.colour = colour
        self.bucketCount = bucketCount
    }

    /// The view body.
    public var body: some View {
        SparklineShape(values: series.normalised(count: bucketCount, endingAt: now))
            .stroke(colour.color, style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
            .frame(minHeight: Spacing.extraLarge)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Self.accessibilityLabel(title: title, series: series, now: now))
    }

    /// Spoken label: title, window and peak.
    public static func accessibilityLabel(title: String, series: SparklineSeries, now: Date) -> String {
        guard let peak = series.peak(endingAt: now) else {
            return MacStrings.last30SecondsNoData(String(title))
        }
        return MacStrings.last30SecondsPeak(String(title), String(UIFormat.rate(peak)))
    }
}

private nonisolated struct SparklineShape: Shape {
    let values: [Double]

    func path(in rect: CGRect) -> Path {
        var path = Path()
        guard values.count > 1 else { return path }
        let step = rect.width / CGFloat(values.count - 1)
        for (index, value) in values.enumerated() {
            let point = CGPoint(x: rect.minX + CGFloat(index) * step, y: rect.maxY - CGFloat(value) * rect.height)
            if index == 0 {
                path.move(to: point)
            } else {
                path.addLine(to: point)
            }
        }
        return path
    }
}
