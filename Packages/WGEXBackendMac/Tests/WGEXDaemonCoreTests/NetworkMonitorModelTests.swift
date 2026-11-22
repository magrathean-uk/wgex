// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct UnderlayRecording: Decodable {
    struct Event: Decodable {
        let ipv4: [String: String]
        let ipv6: [String: String]
        let indexes: [String: UInt32]
        let resolvers: [String]
        let mtu: UInt16
        let satisfied: Bool
    }

    let synthetic: Bool
    let events: [Event]
}

private struct NetworkMonitorModelTests {
    @Test
    func `synthetic configd notification corpus moves each family and observes loss of underlay`() throws {
        let text = try NetworkPortHarness.fixture("Underlay/notifications.json")
        let recording = try JSONDecoder().decode(UnderlayRecording.self, from: Data(text.utf8))
        #expect(recording.synthetic)
        var model = UnderlayMonitorModel(), snapshots: [UnderlaySnapshot] = []
        for event in recording.events {
            let snapshot = UnderlayMonitorModel.snapshot(
                ipv4: event.ipv4, ipv6: event.ipv6, indexes: event.indexes, resolvers: event.resolvers,
            )
            let changed = model.receive(UnderlayEvent(snapshot: snapshot, satisfied: event.satisfied, mtu: event.mtu))
            #expect(changed); snapshots.append(snapshot)
        }
        #expect(snapshots.map(\.v4) == [4, 8, nil, nil])
        #expect(snapshots.map(\.v6) == [4, 4, 8, nil])
        #expect(model.current?.satisfied == false)
    }

    @Test
    func `route monitor filters self and debounces recorded notifications for three hundred ms`() throws {
        var model = RouteMonitorModel(ownPID: 4321)
        let hex = try NetworkPortHarness.fixture("RouteMessages/delete-v4.hex")
        let bytes = try hex.split(whereSeparator: \.isWhitespace).map { try #require(UInt8($0, radix: 16)) }
        let notification = try RouteNotification.parse(Data(bytes))
        let received13 = !model.receive(notification, at: .zero)
        #expect(received13)
        let foreign = RouteNotification(type: 2, index: 7, pid: 999)
        let received15 = model.receive(foreign, at: .zero)
        #expect(received15)
        let received16 = !model.takeReconciliation(at: .milliseconds(299))
        #expect(received16)
        let received17 = model.receive(foreign, at: .milliseconds(200))
        #expect(received17)
        let received18 = !model.takeReconciliation(at: .milliseconds(499))
        #expect(received18)
        let received19 = model.takeReconciliation(at: .milliseconds(500))
        #expect(received19)
        let received20 = !model.takeReconciliation(at: .seconds(1))
        #expect(received20)
        let received21 = !model.receive(RouteNotification(type: 4, index: 7, pid: 999), at: .zero)
        #expect(received21)
    }

    @Test(arguments: [UInt8(12), 13, 14])
    func `interface notification headers have no pid`(type: UInt8) throws {
        var bytes = [UInt8](repeating: 0, count: type == 14 ? 112 : 20)
        bytes[0] = UInt8(bytes.count); bytes[2] = 5; bytes[3] = type; bytes[12] = 7
        let event = try RouteNotification.parse(Data(bytes))
        #expect(event.index == 7); #expect(event.pid == nil)
        var model = RouteMonitorModel(ownPID: 123)
        let received31 = model.receive(event, at: .zero)
        #expect(received31)
        #expect(throws: (any Error).self) { try RouteNotification.parse(Data(bytes.prefix(13))) }
    }

    @Test
    func `recorded configd primary changes select each family independently and MTU is bounded`() {
        var model = UnderlayMonitorModel()
        let first = UnderlayMonitorModel.snapshot(
            ipv4: ["PrimaryInterface": "en0"], ipv6: ["PrimaryInterface": "en1"], indexes: ["en0": 4, "en1": 6], resolvers: ["192.0.2.53"],
        )
        #expect(first.v4 == 4); #expect(first.v6 == 6)
        let received42 = model.receive(UnderlayEvent(snapshot: first, satisfied: true))
        #expect(received42)
        let received43 = !model.receive(UnderlayEvent(snapshot: first, satisfied: true))
        #expect(received43)
        let second = UnderlayMonitorModel.snapshot(
            ipv4: ["PrimaryInterface": "en2"], ipv6: [:], indexes: ["en2": 8], resolvers: ["198.51.100.53"],
        )
        let received47 = model.receive(UnderlayEvent(snapshot: second, satisfied: true, mtu: 1400))
        #expect(received47)
        #expect(model.current?.snapshot.v6 == nil)
        #expect(UnderlayMonitorModel.mtu(override: nil, underlay: 1500, carrier: false) == 1420)
        #expect(UnderlayMonitorModel.mtu(override: 1300, underlay: 1500, carrier: false) == 1300)
        #expect(UnderlayMonitorModel.mtu(override: 1500, underlay: 1400, carrier: false) == 1320)
        #expect(UnderlayMonitorModel.mtu(override: nil, underlay: 9000, carrier: true) == 1420)
        #expect(UnderlayMonitorModel.mtu(override: nil, underlay: 9000, carrier: false) == 1500)
    }

    @Test(arguments: [5, 6], [110, 111])
    func `wake uses strict handshake and continuous sleep thresholds`(sleep: Int, handshake: Int) {
        var model = PowerMonitorModel()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        model.sleep(at: .zero)
        let decision = model.wake(at: .seconds(sleep), wallNow: now, lastHandshake: now.addingTimeInterval(-Double(handshake)))
        #expect(decision.bumpSockets)
        #expect(decision.forceHandshake == (sleep > 5 || handshake > 110))
        #expect(model.awaitingHandshake == decision.forceHandshake)
        model.handshakeCompleted(); #expect(!model.awaitingHandshake)
    }

    @Test(arguments: [UInt32(0), 501, 502], [false, true])
    func `console change stops owner tunnel unless boot enabled and never resumes automatically`(uid: UInt32, boot: Bool) {
        var model = LoginSessionMonitorModel(consoleUID: 501)
        let received71 = model.receive(uid, ownerUID: 501, startBeforeLogin: boot) == (!boot && uid != 501)
        #expect(received71)
        let received72 = !model.receive(501, ownerUID: 501, startBeforeLogin: boot)
        #expect(received72)
    }

    @Test
    func `kill switch verifies all external triggers and every five seconds while enforcing`() async {
        let monitor = KillSwitchMonitor()
        #expect(await !monitor.shouldVerify(trigger: .periodic, enforcing: false, now: .zero))
        #expect(await monitor.shouldVerify(trigger: .periodic, enforcing: true, now: .zero))
        #expect(await !monitor.shouldVerify(trigger: .periodic, enforcing: true, now: .seconds(4)))
        #expect(await monitor.shouldVerify(trigger: .periodic, enforcing: true, now: .seconds(5)))
        for trigger in [ProtectionTrigger.route, .configuration, .wake, .buildChanged] {
            #expect(await monitor.shouldVerify(trigger: trigger, enforcing: true, now: .seconds(5)))
        }
    }

    @Test
    func `captive continuous expiry ignores wall movement allows one extension and closes after restart`() throws {
        let wall = Date(timeIntervalSince1970: 1_700_000_000)
        let initial = try CaptiveWindowModel.open(seconds: 30, maximum: 60, continuous: .zero, wall: wall)
        #expect(!CaptiveWindowModel.isExpired(initial, continuous: .seconds(29)))
        #expect(CaptiveWindowModel.isExpired(initial, continuous: .seconds(30)))
        #expect(CaptiveWindowModel.isExpired(initial, continuous: .zero, sameProcess: false))
        let extended = try CaptiveWindowModel.extend(
            initial,
            seconds: 60,
            maximum: 60,
            continuous: .seconds(20),
            wall: wall.addingTimeInterval(-1000),
        )
        #expect(extended.extended); #expect(extended.expiresAtContinuousSeconds == 80)
        #expect(throws: DaemonFailure.captiveAlreadyExtended) {
            try CaptiveWindowModel.extend(extended, seconds: 1, maximum: 60, continuous: .seconds(21), wall: wall)
        }
        #expect(throws: DaemonFailure.captiveInvalidDuration) { try CaptiveWindowModel.open(
            seconds: 61,
            maximum: 60,
            continuous: .zero,
            wall: wall,
        ) }
        #expect(throws: DaemonFailure.captiveExpired) {
            try CaptiveWindowModel.extend(initial, seconds: 1, maximum: 60, continuous: .seconds(30), wall: wall)
        }
    }

    @Test
    func `captive deadlines retain subsecond precision and decode old journal records`() throws {
        let wall = Date(timeIntervalSince1970: 1_700_000_000)
        let window = try CaptiveWindowModel.open(seconds: 10, maximum: 60, continuous: .milliseconds(750), wall: wall)
        #expect(!CaptiveWindowModel.isExpired(window, continuous: .milliseconds(10749)))
        #expect(CaptiveWindowModel.isExpired(window, continuous: .milliseconds(10750)))
        let original = CaptiveWindowRecord(expiresAtWall: wall, expiresAtContinuousSeconds: 10)
        let encoded = try JSONEncoder().encode(original)
        var fields = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        fields.removeValue(forKey: "wasExtended"); fields.removeValue(forKey: "expiresAtContinuousAttoseconds")
        let decoded = try JSONDecoder().decode(CaptiveWindowRecord.self, from: JSONSerialization.data(withJSONObject: fields))
        #expect(!decoded.extended); #expect(decoded.continuousDeadline == .seconds(10))
    }
}
