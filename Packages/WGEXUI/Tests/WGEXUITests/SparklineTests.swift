// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXUI

private struct SparklineTests {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)

    @Test
    func `samples older than the window are dropped`() {
        var series = SparklineSeries()
        for second in 0 ... 60 {
            series.append(Double(second), at: start.addingTimeInterval(Double(second)))
        }
        #expect(series.samples.count == 31)
        #expect(series.samples.first?.value == 30)
        #expect(series.samples.last?.value == 60)
    }

    @Test
    func `downsampling keeps one bucket per slot and preserves peaks`() {
        var series = SparklineSeries()
        for tenth in 1 ... 300 {
            let value = tenth == 155 ? 1000.0 : 10
            series.append(value, at: start.addingTimeInterval(Double(tenth) / 10))
        }
        let end = start.addingTimeInterval(30)
        let buckets = series.buckets(count: 30, endingAt: end)
        #expect(buckets.count == 30)
        #expect(buckets.allSatisfy { $0 != nil })
        #expect(buckets[15] == 1000)
        #expect(buckets.compactMap(\.self).filter { $0 == 1000 }.count == 1)
        #expect(series.peak(endingAt: end) == 1000)
        let normalised = series.normalised(count: 30, endingAt: end)
        #expect(normalised[15] == 1)
        #expect(normalised[0] == 0.01)
    }

    @Test
    func `gaps stay empty and out-of-order samples are ordered`() {
        var series = SparklineSeries()
        series.append(5, at: start.addingTimeInterval(29))
        series.append(7, at: start.addingTimeInterval(1))
        series.append(.nan, at: start.addingTimeInterval(2))
        series.append(-1, at: start.addingTimeInterval(3))
        #expect(series.samples.map(\.value) == [7, 5])
        let buckets = series.buckets(count: 3, endingAt: start.addingTimeInterval(30))
        #expect(buckets == [7, nil, 5])
    }

    @Test
    func `an empty series draws flat and reports no data`() {
        let series = SparklineSeries()
        #expect(series.normalised(count: 4, endingAt: start) == [0, 0, 0, 0])
        #expect(series.peak(endingAt: start) == nil)
        #expect(series.buckets(count: 0, endingAt: start).isEmpty)
        #expect(Sparkline.accessibilityLabel(title: "Download", series: series, now: start) == "Download, last 30 seconds, no data")
    }

    @Test
    func `the label names the peak`() {
        let series = SparklineSeries(samples: [.init(time: start, value: 1_234_567)])
        #expect(Sparkline.accessibilityLabel(title: "Download", series: series, now: start) == "Download, last 30 seconds, peak 1.2 MB/s")
    }
}
