// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXDiagnostics

private struct LogRingTests {
    @Test
    func `wrap retains the newest 4096 entries with timestamps and categories`() {
        let ring = LogRing()
        let date = Date(timeIntervalSince1970: 123)
        for index in 0 ..< 5000 {
            ring.append("line \(index)", category: .dns, date: date)
        }
        let lines = ring.redactedLines(using: Redactor())
        #expect(ring.entryCount == 4096)
        #expect(lines.count == 4096)
        #expect(lines.first?.message == "line 904")
        #expect(lines.last?.message == "line 4999")
        #expect(lines.allSatisfy { $0.date == date && $0.category == "dns" })
    }

    @Test
    func `continuations reconstruct utf8 and evict whole messages across wrap`() {
        let ring = LogRing()
        let text = String(repeating: ".", count: 510) + "🦊" + String(repeating: ".", count: 600)
        ring.append(text, category: .provider)
        #expect(ring.entryCount == 3)
        #expect(ring.redactedLines(using: Redactor()).first?.message == text)
        for _ in 0 ..< 4094 {
            ring.append("next", category: .app)
        }
        #expect(ring.entryCount == 4094)
        #expect(ring.redactedLines(using: Redactor()).allSatisfy { $0.message == "next" })
        ring.append(text, category: .engine)
        #expect(ring.entryCount == 4096)
        #expect(ring.redactedLines(using: Redactor()).last?.message == text)
    }

    @Test
    func `empty lines survive and oversized messages never expose fragments`() {
        let ring = LogRing()
        ring.append("", category: .app); ring.append("tail", category: .store)
        #expect(ring.redactedLines(using: Redactor()).map(\.message) == ["", "tail"])
        ring.append(String(repeating: "x", count: LogRing.capacity * LogRing.entryByteCount), category: .app)
        #expect(ring.entryCount == 2)
    }

    @Test
    func `concurrent writes retain complete messages`() async {
        let ring = LogRing()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 8 {
                group.addTask { for _ in 0 ..< 100 {
                    ring.append(String(repeating: ".", count: 700), category: .xpc)
                } }
            }
        }
        #expect(ring.entryCount == 1600)
        let lines = ring.redactedLines(using: Redactor())
        #expect(lines.count == 800)
        #expect(lines.allSatisfy { $0.message.utf8.count == 700 })
    }
}
