// SPDX-License-Identifier: MIT

#if os(macOS) && WGEX_ENGINE_TEST_SUPPORT
    import CWGEXEngineTest
    import Darwin
    import Foundation
    import Testing
    import WGEXCore
    import WGEXEngine
    import WGEXEngineInterface

    private final class NetstackPair: Sendable {
        let id: Int64
        let a: EngineActor
        let b: EngineActor

        init() throws {
            let left = CallbackBox()
            let right = CallbackBox()
            var pa = unsafe wgex_create_params()
            var pb = unsafe wgex_create_params()
            unsafe pa.log_level = 1
            unsafe pb.log_level = 1
            unsafe pa.log = CallbackBox.logTrampoline
            unsafe pa.event = CallbackBox.eventTrampoline
            unsafe pb.log = CallbackBox.logTrampoline
            unsafe pb.event = CallbackBox.eventTrampoline
            // Both boxes transfer into the adopting actors before these locals are released.
            unsafe pa.log_ctx = Unmanaged.passUnretained(left).toOpaque()
            unsafe pa.event_ctx = pa.log_ctx
            unsafe pb.log_ctx = Unmanaged.passUnretained(right).toOpaque()
            unsafe pb.event_ctx = pb.log_ctx
            // The pair copies the structs synchronously; only the boxes escape.
            let pair = unsafe wgex_test_pair_create(nil, &pa, &pb)
            guard pair > 0 else { throw EngineError.internal }
            id = pair
            a = EngineActor(adopting: wgex_test_pair_engine(pair, 0), callbacks: left)
            b = EngineActor(adopting: wgex_test_pair_engine(pair, 1), callbacks: right)
        }

        deinit { _ = wgex_test_pair_destroy(id) }

        func request(from: Int32) throws -> Int {
            // The archive returns owned public HTTP JSON; no pair_info (which contains keys) is requested.
            let result = unsafe wgex_test_pair_http_get(id, from, "/", 5000)
            guard let result = unsafe result else { throw EngineError.internal }
            defer { unsafe wgex_free(result) }
            let text = unsafe String(cString: result)
            let object = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
            return object?["status"] as? Int ?? 0
        }
    }

    /// Serialised only for the descriptor baseline and process-wide configure-before-create rule.
    @Suite(.serialized)
    private struct EngineActorTests {
        @Test
        func `loopback HTTP callbacks statistics and session operations`() async throws {
            #expect(wgex_test_ping() == 1)
            let pair = try NetstackPair()
            let logs = Task { () -> Int in
                var count = 0
                for await _ in pair.a.logs {
                    count += 1
                }
                return count
            }
            let events = Task { () -> [EngineEvent] in
                var received: [EngineEvent] = []
                for await event in pair.a.events {
                    received.append(event)
                }
                return received
            }
            defer { logs.cancel(); events.cancel() }
            #expect(try pair.request(from: 0) == 200)
            #expect(try pair.request(from: 1) == 200)
            try await exerciseSession(pair)
            try await pair.a.setTransport(.udp)
            try await pair.a.bumpSockets(v4: nil, v6: nil)
            #expect(try pair.request(from: 0) == 200)
            // Shutdown drains callbacks while Go is still producing socket/device logs.
            await pair.a.shutdown()
            await pair.a.shutdown()
            await pair.b.shutdown()
            #expect(await logs.value > 0)
            let received = await events.value
            #expect(received.contains {
                if case .handshakeCompleted = $0 {
                    true
                } else {
                    false
                }
            })
            #expect(received.contains {
                if case .rx = $0 {
                    true
                } else {
                    false
                }
            })
            await #expect(throws: EngineError.invalidHandle) { try await pair.a.statistics() }
        }

        private func exerciseSession(_ pair: NetstackPair) async throws {
            let before = try await pair.a.statistics()
            let peer = try #require(before.peers.first)
            #expect(peer.rxBytes > 0)
            #expect(peer.txBytes > 0)
            let original = try #require(peer.lastHandshake)
            let endpoint = try #require(peer.endpoint)
            try await pair.a.updateEndpoints([peer.publicKey: endpoint])
            #expect(try pair.request(from: 0) == 200)
            // Keep sampling beyond the health tick: endpoint update must keep the same session.
            try await Task.sleep(for: .milliseconds(1200))
            #expect(try await pair.a.statistics().peers.first?.lastHandshake == original)
            try await pair.a.forceHandshake()
            var changed = false
            for _ in 0 ..< 100 {
                if let latest = try await pair.a.statistics().peers.first?.lastHandshake, latest > original {
                    changed = true; break
                }
                try await Task.sleep(for: .milliseconds(20))
            }
            #expect(changed)
        }

        @Test
        func `packet descriptor lifecycle cycles`() async throws {
            let cycles = Int(ProcessInfo.processInfo.environment["WGEX_ENGINE_CYCLES"] ?? "500") ?? 500
            let baseline = try FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count
            for _ in 0 ..< cycles {
                try await oneCycle()
            }
            let after = try FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count
            #expect(after <= baseline + 2) // Go initialises its process-wide poll descriptors once.
            try await holdForLeakMeasurement()
        }

        private func oneCycle() async throws {
            var fds: [Int32] = [0, 0]
            // socketpair fills two stack-owned descriptors. No kernel tunnel is created.
            let code = unsafe socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
            guard code == 0 else { throw EngineError.tun }
            do {
                let limits: EngineConfiguration.ProcessLimits? = ProcessInfo.processInfo.environment["WGEX_ENGINE_PROCESS_LIMITS"] == "1"
                    ? .constrained : nil
                let engine = try EngineActor(configuration: EngineConfiguration(
                    tun: .packetDescriptor(descriptor: fds[0], mtu: 1420), processLimits: limits,
                ))
                let document = try publicDocument("replace_peers=true\nlisten_port=0\n")
                try await engine.setConfiguration(document)
                try await engine.up()
                try await engine.bumpSockets(v4: nil, v6: nil)
                try await engine.down()
                await engine.shutdown()
                await engine.shutdown()
                await #expect(throws: EngineError.invalidHandle) { try await engine.up() }
            } catch {
                close(fds[0]); close(fds[1]); throw error
            }
            close(fds[0]); close(fds[1])
        }

        @Test
        func `eight concurrent owners drain their Go callbacks`() async throws {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0 ..< 8 {
                    group.addTask {
                        for _ in 0 ..< 25 {
                            try await oneCycle()
                        }
                    }
                }
                try await group.waitForAll()
            }
        }

        private func holdForLeakMeasurement() async throws {
            if let ready = ProcessInfo.processInfo.environment["WGEX_ENGINE_LEAK_READY"] {
                // The external scanner waits for this public marker, then scans the live test process.
                try "ready".write(toFile: ready, atomically: true, encoding: .utf8)
                try await Task.sleep(for: .seconds(30))
            }
        }

        @Test
        func `failed creation and first configuration are cleaned up`() async throws {
            #expect(throws: EngineError.invalidArgument) {
                _ = try EngineActor(configuration: EngineConfiguration(tun: .packetDescriptor(descriptor: -1, mtu: 1420)))
            }
            var fds: [Int32] = [0, 0]
            // Valid socketpair ownership is local and both descriptors are closed on every path.
            guard unsafe socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else { throw EngineError.tun }
            defer { close(fds[0]); close(fds[1]) }
            let engine = try EngineActor(configuration: EngineConfiguration(tun: .packetDescriptor(descriptor: fds[0], mtu: 1420)))
            let bad = try publicDocument("replace_peers=true\nlisten_port=65536\n")
            await #expect(throws: EngineError.deviceClosed) { try await engine.setConfiguration(bad) }
            await engine.shutdown()
        }

        @Test
        func `tun read failure reaches Swift within one second`() async throws {
            let pair = try NetstackPair()
            let started = ContinuousClock.now
            let received = Task { () -> EngineEvent? in
                for await event in pair.a.events {
                    if case .engine(.deviceClosed) = event {
                        return event
                    }
                }
                return nil
            }
            defer { received.cancel() }
            #expect(wgex_test_pair_fail_tun(pair.id, 0) == 0)
            // Finish the stream at the deadline, so a lost callback fails rather than hangs.
            let deadline = Task {
                try await Task.sleep(for: .seconds(1))
                await pair.a.shutdown()
            }
            let event = await received.value
            deadline.cancel()
            #expect(event == .engine(.deviceClosed(.tunReadError)))
            #expect(started.duration(to: .now) < .seconds(1))
            await #expect(throws: EngineError.deviceClosed) { try await pair.a.up() }
            try await pair.a.down()
            let document = try publicDocument("replace_peers=true\nlisten_port=0\n")
            await #expect(throws: EngineError.deviceClosed) { try await pair.a.setConfiguration(document) }
            await pair.a.shutdown()
            await pair.b.shutdown()
        }

        @Test
        func `lifecycle callbacks are retained`() async {
            let box = CallbackBox()
            let context = unsafe Unmanaged.passUnretained(box).toOpaque()
            for json in [
                #"{"kind":"engine","event":"configRestored"}"#,
                #"{"kind":"engine","event":"socketsBumped","ok":false}"#,
                #"{"kind":"engine","event":"deviceClosed","reason":2}"#,
                #"{"kind":"transport","event":"carrierDisconnected","reason":"fixture"}"#,
            ] {
                json.withCString { unsafe CallbackBox.eventTrampoline(context, 0, $0, json.utf8.count) }
            }
            box.finish()
            var events: [EngineEvent] = []
            for await event in box.events {
                events.append(event)
            }
            #expect(events == [
                .engine(.configRestored),
                .engine(.socketsBumped(ok: false)),
                .engine(.deviceClosed(.configurationRejected)),
                .transport(.carrierDisconnected(reason: "fixture")),
            ])
        }

        @Test
        func `bounded callback loss is reported and finished boxes reject callbacks`() async {
            let box = CallbackBox(capacity: 1)
            // These synchronous C-style calls use a live box and a scoped string buffer.
            let context = unsafe Unmanaged.passUnretained(box).toOpaque()
            for _ in 0 ..< 4 {
                "test".withCString { unsafe CallbackBox.logTrampoline(context, 0, $0, 4) }
            }
            box.finish()
            "late".withCString { unsafe CallbackBox.logTrampoline(context, 0, $0, 4) }
            var count = 0
            for await _ in box.logs {
                count += 1
            }
            #expect(count == 1)
            var last: EngineCallbackDrops?
            for await value in box.drops {
                last = value
            }
            #expect(last?.logs == 3)
        }

        @Test(arguments: [
            #"{"private_key":null}"#,
            #"{"nested":[{"preshared_key":""}]}"#,
            #"{"nested":{"private_key":0},"nested":{}}"#,
            #"{"pr\u0069vate_key":false}"#,
        ])
        func `statistics guard rejects secret names anywhere`(json: String) {
            #expect(throws: UAPIStatsError.secretKey) { try UAPIStatsDecoder.decode(Array(json.utf8)) }
        }

        @Test(arguments: zip(
            [Int32(-1), -2, -3, -4, -5, -6, -7, -8, -9, -99, -123],
            [
                EngineError.invalidArgument,
                .outOfMemory,
                .invalidHandle,
                .tun,
                .bind,
                .config,
                .up,
                .state,
                .deviceClosed,
                .internal,
                .unknown(code: -123),
            ],
        ))
        func `every ABI error has a distinct mapping`(code: Int32, expected: EngineError) {
            #expect(EngineError(code: code) == expected)
            #expect(EngineError(code: 0) == nil)
        }

        private func publicDocument(_ text: String) throws -> UAPIDocument {
            // An all-zero private key explicitly disables identity; it is not secret material.
            // Full replacements always include the key and listen port, even in lifecycle fixtures.
            let complete = "private_key=" + String(repeating: "0", count: 64) + "\n" + text
            var result: SecretBytes?
            try Array(complete.utf8).withUnsafeBytes { raw in result = try unsafe SecretBytes(copying: raw) }
            guard let bytes = consume result else { throw EngineError.internal }
            return UAPIDocument(bytes: bytes)
        }
    }
#endif
