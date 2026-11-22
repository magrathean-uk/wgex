// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

private actor EventGate {
    var count = 0
    var events: [Event] = []
    var pending: CheckedContinuation<Void, Never>?
    func receive(_ bytes: Data) async {
        count += 1
        if let event = try? WireCodec.decode(Event.self, from: bytes) {
            events.append(event)
        }
        if count == 1 {
            await withCheckedContinuation { pending = $0 }
        }
    }

    func release() {
        pending?.resume(); pending = nil
    }
}

private struct EventQueueTests {
    @Test
    func `thirty two queued events drop subscription while requests remain usable`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1)
        let gate = EventGate()
        let transport = try await handshaken(dispatcher, callbacks: .init(event: { await gate.receive($0) }))
        _ = try await call(transport, .subscribeEvents(includeLogs: true))
        let event = Event.log(.init(date: Date(timeIntervalSince1970: 0), category: "test", message: "redacted", profileID: nil))
        await dispatcher.publish(event, profileID: nil)
        while await gate.count == 0 {
            await Task.yield()
        }
        for _ in 0 ..< 33 {
            await dispatcher.publish(event, profileID: nil)
        }
        await gate.release()
        for _ in 0 ..< 1000 {
            if await gate.events.last == .subscriptionLost {
                break
            }
            await Task.yield()
        }
        #expect(await gate.events.last == .subscriptionLost)
        #expect(await gate.count == 33)
        #expect(try await call(transport, .status).isMeasuredIdle)
        #expect(try await call(transport, .subscribeEvents(includeLogs: false)) == .ok)
        await transport.invalidate()
    }
}
