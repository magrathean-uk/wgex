// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
// The fake backend links only into Debug and Lab builds; Release never imports WGEXTesting.
#if DEBUG || WGEX_LAB_BUILD
    import Foundation
    import Testing
    @testable import WGEX
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// Tunnel list and detail sequences against the fake backend, with the model's status subscription running.
    @MainActor @Suite(.serialized)
    private struct IOSTunnelListTests {
        private struct Rig {
            let model: AppModel
            let fake: FakeTunnelBackend
            let runner: Task<Void, Never>

            func finish() async {
                await TunnelListSupport.finish(model, runner)
            }
        }

        private func rig(_ names: [String]) async throws -> Rig {
            let (model, fake, runner) = try await TunnelListSupport.rig(names)
            return Rig(model: model, fake: fake, runner: runner)
        }

        private func starts(_ fake: FakeTunnelBackend) -> [FakeTunnelBackend.Call] {
            fake.calls.filter {
                switch $0 {
                case .start, .stop: true
                default: false
                }
            }
        }

        private func statisticsCalls(_ fake: FakeTunnelBackend) -> Int {
            fake.calls.count(where: { $0 == .statistics })
        }

        @Test
        func `a switch turns its tunnel on and off`() async throws {
            let rig = try await rig(["Home"])
            let model = rig.model
            let home = try #require(model.profiles.first).id
            #expect(!model.isTunnelOn(home))
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) && model.status.protection == .protected }
            #expect(model.activeProfileID == home)
            await model.setTunnel(home, on: false)
            try await TunnelListSupport.until { !model.isTunnelOn(home) }
            #expect(starts(rig.fake) == [.start(home, transport: nil), .stop(home)])
            #expect(model.userInitiated)
            await rig.finish()
        }

        @Test
        func `switching another tunnel on stops the first`() async throws {
            let rig = try await rig(["Home", "Office"])
            let model = rig.model
            let home = model.profiles[0].id, office = model.profiles[1].id
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            await model.setTunnel(office, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(office) && model.status.protection == .protected }
            #expect(!model.isTunnelOn(home))
            #expect(model.activeProfileID == office)
            #expect(model.selectedProfileID == office)
            #expect(starts(rig.fake) == [.start(home, transport: nil), .stop(home), .start(office, transport: nil)])
            await rig.finish()
        }

        @Test
        func `a start or stop made outside the app moves the switches`() async throws {
            let rig = try await rig(["Home", "Office"])
            let model = rig.model
            let home = model.profiles[0].id, office = model.profiles[1].id
            // Each import selects the profile it saved, so Office is selected now; the user picks Home in the list.
            #expect(model.selectedProfileID == office)
            model.selectedProfileID = home
            // Settings > VPN or on-demand brings Office up: the backend names it in its status.
            var external = TunnelStatus.idle
            external.phase = .active(Generation(rawValue: 7))
            external.protection = .protected
            external.activeProfileID = office
            rig.fake.publish(external)
            try await TunnelListSupport.until { model.isTunnelOn(office) }
            #expect(!model.isTunnelOn(home))
            #expect(model.selectedProfileID == office)
            #expect(starts(rig.fake).isEmpty)
            // And stops it there again.
            rig.fake.publish(.idle)
            try await TunnelListSupport.until { !model.isTunnelOn(office) }
            #expect(model.activeProfileID == nil)
            #expect(!model.userInitiated)
            await rig.finish()
        }

        @Test
        func `editing the active tunnel applies in place and shows progress until it is back`() async throws {
            let rig = try await rig(["Home"])
            let model = rig.model
            let home = try #require(model.profiles.first)
            let gate = InstallGate(fake: rig.fake)
            model.installProfile = { try await gate.install($0) }
            await model.setTunnel(home.id, on: true)
            try await TunnelListSupport.until { model.status.phase == .active(Generation(rawValue: 1)) }
            await model.openEditor(home)
            let editor = try #require(model.editor)
            var renamed = try editor.validatedProfile()
            renamed.name = "Home renamed"
            let edit = Task { await model.commitEdit(renamed, model: editor) }
            try await TunnelListSupport.eventually { await gate.waiting == 1 }
            // The provider is reloading the running tunnel; its install has not answered yet.
            #expect(model.applyingProfileID == home.id)
            #expect(model.isBusy)
            await gate.release()
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == nil)
            #expect(model.editor == nil)
            #expect(model.profiles.first?.name == "Home renamed")
            #expect(try await model.store.load(home.id).name == "Home renamed")
            #expect(rig.fake.calls.last == .install(home.id))
            #expect(starts(rig.fake) == [.start(home.id, transport: nil)])
            #expect(model.isTunnelOn(home.id))
            await rig.finish()
        }

        @Test
        func `a failed edit of the active tunnel ends the progress and keeps the tunnel`() async throws {
            let rig = try await rig(["Home"])
            let model = rig.model
            let home = try #require(model.profiles.first)
            await model.setTunnel(home.id, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home.id) && AppModel.isSettled(model.status.phase) }
            await model.openEditor(home)
            let editor = try #require(model.editor)
            var renamed = try editor.validatedProfile()
            renamed.name = "Home renamed"
            rig.fake.faults.arm("install", error: TunnelError.backendUnavailable)
            await model.commitEdit(renamed, model: editor)
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == "Profile edits could not be saved. Reopen the editor to try again.")
            #expect(model.profiles.first?.name == "Home")
            #expect(try await model.store.load(home.id).name == "Home")
            #expect(model.isTunnelOn(home.id))
            #expect(starts(rig.fake) == [.start(home.id, transport: nil)])
            await rig.finish()
        }

        @Test
        func `editing an inactive tunnel shows no progress`() async throws {
            let rig = try await rig(["Home"])
            let model = rig.model
            let home = try #require(model.profiles.first)
            await model.openEditor(home)
            let editor = try #require(model.editor)
            var renamed = try editor.validatedProfile()
            renamed.name = "Home renamed"
            await model.commitEdit(renamed, model: editor)
            #expect(model.applyingProfileID == nil)
            #expect(model.profiles.first?.name == "Home renamed")
            #expect(starts(rig.fake).isEmpty)
            await rig.finish()
        }

        @Test
        func `deleting the active tunnel stops it first`() async throws {
            let rig = try await rig(["Home", "Office"])
            let model = rig.model
            let home = model.profiles[0].id, office = model.profiles[1].id
            await model.setTunnel(office, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(office) }
            await model.deleteProfile(office)
            let calls = rig.fake.calls
            let stop = try #require(calls.firstIndex(of: .stop(office)))
            let remove = try #require(calls.firstIndex(of: .remove(office, purgeSecrets: true)))
            #expect(stop < remove)
            #expect(model.profiles.map(\.id) == [home])
            #expect(try await model.store.list().map(\.id) == [home])
            try await TunnelListSupport.until { !model.isTunnelOn(office) }
            #expect(model.activeProfileID == nil)
            #expect(model.selectedProfileID == home)
            await rig.finish()
        }

        @Test
        func `deleting an inactive tunnel leaves the running one alone`() async throws {
            let rig = try await rig(["Home", "Office"])
            let model = rig.model
            let home = model.profiles[0].id, office = model.profiles[1].id
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            await model.deleteProfile(office)
            #expect(!rig.fake.calls.contains(.stop(office)))
            #expect(model.isTunnelOn(home))
            #expect(model.profiles.map(\.id) == [home])
            await rig.finish()
        }

        @Test
        func `statistics are sampled only while a detail watches the running tunnel`() async throws {
            let rig = try await rig(["Home"])
            let model = rig.model
            model.statisticsInterval = .milliseconds(20)
            let home = try #require(model.profiles.first)
            let peer = try #require(home.peers.first).publicKey
            rig.fake.setStatistics(TunnelStatistics(
                generation: 1, sampledAt: Date(), interfaceName: "utun4", listenPort: nil,
                peers: [PeerStatistics(
                    publicKey: peer, endpoint: nil, lastHandshake: Date(), rxBytes: 1500, txBytes: 700, persistentKeepalive: nil,
                )],
            ))
            // Watching while off samples nothing.
            let idle = Task { await model.watchStatistics() }
            try await Task.sleep(for: .milliseconds(100))
            #expect(statisticsCalls(rig.fake) == 0)
            #expect(model.statistics == nil)
            idle.cancel()
            await idle.value
            // Running but not watched: nothing is polled.
            await model.setTunnel(home.id, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home.id) }
            try await Task.sleep(for: .milliseconds(100))
            #expect(statisticsCalls(rig.fake) == 0)
            // Watched: about once per interval.
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { statisticsCalls(rig.fake) >= 3 }
            #expect(model.statistics?.peers.first?.rxBytes == 1500)
            #expect(model.statistics?.interfaceName == "utun4")
            // Hidden: the view's task is cancelled and polling stops.
            watcher.cancel()
            await watcher.value
            #expect(model.statistics == nil)
            let sampled = statisticsCalls(rig.fake)
            try await Task.sleep(for: .milliseconds(100))
            #expect(statisticsCalls(rig.fake) == sampled)
            await rig.finish()
        }

        @Test
        func `a failed sample shows nothing rather than stale counters`() async throws {
            let rig = try await rig(["Home"])
            let model = rig.model
            model.statisticsInterval = .milliseconds(20)
            let home = try #require(model.profiles.first)
            await model.setTunnel(home.id, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home.id) }
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { model.statistics != nil }
            rig.fake.faults.arm("statistics", error: TunnelError.backendUnavailable, times: 1000)
            try await TunnelListSupport.until { model.statistics == nil }
            watcher.cancel()
            await watcher.value
            await rig.finish()
        }
    }

    /// Statistics bound to their tunnel, and the backend subscription asked for once per tunnel.
    @MainActor @Suite(.serialized)
    private struct IOSTunnelStatisticsTests {
        private func rig(_ names: [String]) async throws -> (AppModel, FakeTunnelBackend, Task<Void, Never>) {
            let rig = try await TunnelListSupport.rig(names)
            rig.0.statisticsInterval = .milliseconds(20)
            return rig
        }

        private func finish(_ model: AppModel, _ runner: Task<Void, Never>) async {
            await TunnelListSupport.finish(model, runner)
        }

        private static func sample(_ rx: UInt64) throws -> TunnelStatistics {
            try TunnelStatistics(generation: 1, sampledAt: Date(), interfaceName: "utun4", listenPort: nil, peers: [PeerStatistics(
                publicKey: PublicKey(rawValue: Data(repeating: 1, count: 32)), endpoint: nil, lastHandshake: Date(),
                rxBytes: rx, txBytes: 0, persistentKeepalive: nil,
            )])
        }

        @Test
        func `a read that outlives a switch is dropped and never shown for the new tunnel`() async throws {
            let (model, _, runner) = try await rig(["Home", "Office"])
            let home = model.profiles[0].id, office = model.profiles[1].id
            let gate = try SampleGate(Self.sample(1500))
            model.readStatistics = { await gate.read() }
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { model.statisticsProfileID == home }
            #expect(model.statistics?.peers.first?.rxBytes == 1500)
            // Hold the next read of Home, then switch to Office while it is in flight.
            await gate.hold()
            try await TunnelListSupport.eventually { await gate.isHeld }
            let reads = await gate.reads
            await model.setTunnel(office, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(office) }
            #expect(model.statistics == nil)
            #expect(model.statisticsProfileID == nil)
            // Home's late reply arrives; the next read is held too, so the dropped result is observable.
            try await gate.release(Self.sample(1500), keepHolding: true)
            try await TunnelListSupport.eventually {
                let readCount = await gate.reads
                let held = await gate.isHeld
                return readCount == reads + 1 && held
            }
            #expect(model.statistics == nil)
            #expect(model.statisticsProfileID == nil)
            try await gate.release(Self.sample(42), keepHolding: false)
            try await TunnelListSupport.until { model.statisticsProfileID == office }
            #expect(model.statistics?.peers.first?.rxBytes == 42)
            watcher.cancel()
            await watcher.value
            await finish(model, runner)
        }

        @Test
        func `a read that outlives a switch away and back is still dropped`() async throws {
            let (model, fake, runner) = try await rig(["Home", "Office"])
            let home = model.profiles[0].id, office = model.profiles[1].id
            let gate = try SampleGate(Self.sample(1500))
            model.readStatistics = { await gate.read() }
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { model.statisticsProfileID == home }
            // Hold Home's next read, switch to Office and back to Home while it is in flight.
            await gate.hold()
            try await TunnelListSupport.eventually { await gate.isHeld }
            let reads = await gate.reads
            await model.setTunnel(office, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(office) }
            await model.setTunnel(home, on: true)
            // The model has taken every status of the switch, so no later owner change can clear a stale sample.
            try await TunnelListSupport.until { model.isTunnelOn(home) && model.status == fake.currentStatus }
            #expect(model.statistics == nil)
            // The first run's late reply names the same tunnel but must not be shown; the next read is held too.
            try await gate.release(Self.sample(1500), keepHolding: true)
            try await TunnelListSupport.eventually {
                let readCount = await gate.reads
                let held = await gate.isHeld
                return readCount == reads + 1 && held
            }
            #expect(model.statistics == nil)
            #expect(model.statisticsProfileID == nil)
            try await gate.release(Self.sample(42), keepHolding: false)
            try await TunnelListSupport.until { model.statisticsProfileID == home }
            #expect(model.statistics?.peers.first?.rxBytes == 42)
            watcher.cancel()
            await watcher.value
            await finish(model, runner)
        }

        @Test
        func `an external start of another tunnel clears the previous tunnel's sample at once`() async throws {
            let (model, fake, runner) = try await rig(["Home", "Office"])
            let home = model.profiles[0].id, office = model.profiles[1].id
            try fake.setStatistics(Self.sample(1500))
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { model.statisticsProfileID == home }
            model.statisticsInterval = .seconds(30)
            try await Task.sleep(for: .milliseconds(50))
            var external = fake.currentStatus
            external.phase = .active(Generation(rawValue: 9))
            external.activeProfileID = office
            fake.publish(external)
            try await TunnelListSupport.until { model.activeProfileID == office }
            #expect(model.statistics == nil)
            #expect(model.statisticsProfileID == nil)
            watcher.cancel()
            await watcher.value
            await finish(model, runner)
        }

        @Test
        func `the subscription uses a supported interval, starts once per tunnel and stops when hidden`() async throws {
            let (model, fake, runner) = try await rig(["Home"])
            let home = try #require(model.profiles.first).id
            let live = LiveRecorder(rejecting: false)
            model.liveStatistics = live
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { fake.calls.count(where: { $0 == .statistics }) >= 4 }
            #expect(await live.calls == [.start(2)])
            #expect((2 ... 3600).contains(AppModel.statisticsSubscriptionInterval))
            // The tunnel stops while watched: the subscription ends; it comes back with the tunnel.
            await model.setTunnel(home, on: false)
            try await TunnelListSupport.eventually { await live.calls == [.start(2), .stop] }
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.eventually { await live.calls == [.start(2), .stop, .start(2)] }
            watcher.cancel()
            await watcher.value
            #expect(await live.calls == [.start(2), .stop, .start(2), .stop])
            await finish(model, runner)
        }

        @Test
        func `a rejected subscription is not asked for again and reads go on`() async throws {
            let (model, fake, runner) = try await rig(["Home"])
            let home = try #require(model.profiles.first).id
            try fake.setStatistics(Self.sample(7))
            let live = LiveRecorder(rejecting: true)
            model.liveStatistics = live
            await model.setTunnel(home, on: true)
            try await TunnelListSupport.until { model.isTunnelOn(home) }
            let watcher = Task { await model.watchStatistics() }
            try await TunnelListSupport.until { fake.calls.count(where: { $0 == .statistics }) >= 6 }
            #expect(await live.calls == [.start(2)])
            #expect(model.statistics?.peers.first?.rxBytes == 7)
            watcher.cancel()
            await watcher.value
            // Nothing was subscribed, so nothing is stopped.
            #expect(await live.calls == [.start(2)])
            await finish(model, runner)
        }
    }

    /// Holds statistics reads on demand, so a reply can arrive after the tunnel changed.
    private actor SampleGate {
        private var held: CheckedContinuation<TunnelStatistics, Never>?
        private var holding = false
        private var next: TunnelStatistics
        private(set) var reads = 0

        init(_ sample: TunnelStatistics) {
            next = sample
        }

        var isHeld: Bool {
            held != nil
        }

        func read() async -> TunnelStatistics {
            reads += 1
            guard holding else { return next }
            return await withCheckedContinuation { held = $0 }
        }

        func hold() {
            holding = true
        }

        func release(_ sample: TunnelStatistics, keepHolding: Bool) {
            holding = keepHolding
            next = sample
            held?.resume(returning: sample)
            held = nil
        }
    }

    /// Records the live-statistics seam; rejects every start when asked, as the provider does an unsupported interval.
    private actor LiveRecorder: LiveStatisticsSource {
        enum Call: Equatable { case start(TimeInterval), stop }
        private(set) var calls: [Call] = []
        private let rejecting: Bool

        init(rejecting: Bool) {
            self.rejecting = rejecting
        }

        func startStatistics(interval: TimeInterval) async throws(TunnelError) {
            calls.append(.start(interval))
            if rejecting {
                throw .invalidConfiguration(.statisticsInterval)
            }
        }

        func stopStatistics() async {
            calls.append(.stop)
        }
    }

    /// Polling and fixture helpers for the tunnel list tests.
    @MainActor
    internal enum TunnelListSupport {
        /// A model with its status loop running and the named profiles imported, in order.
        internal static func rig(_ names: [String]) async throws -> (AppModel, FakeTunnelBackend, Task<Void, Never>) {
            let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
            let fake = try #require(model.backend as? FakeTunnelBackend)
            let runner = Task { await model.run() }
            try await until { !model.statusHistory.isEmpty }
            for name in names {
                try model.importFile(Data(configuration().utf8), name: name, isArchive: false)
                await model.confirmImport()
            }
            #expect(model.profiles.map(\.name) == names)
            return (model, fake, runner)
        }

        internal static func finish(_ model: AppModel, _ runner: Task<Void, Never>) async {
            runner.cancel()
            await runner.value
            try? FileManager.default.removeItem(at: model.container)
        }

        internal static func until(_ condition: () -> Bool, sourceLocation: SourceLocation = #_sourceLocation) async throws {
            for _ in 0 ..< 500 {
                if condition() {
                    return
                }
                try await Task.sleep(for: .milliseconds(10))
            }
            Issue.record("condition not met in time", sourceLocation: sourceLocation)
        }

        internal static func eventually(_ condition: () async -> Bool, sourceLocation: SourceLocation = #_sourceLocation) async throws {
            for _ in 0 ..< 500 {
                if await condition() {
                    return
                }
                try await Task.sleep(for: .milliseconds(10))
            }
            Issue.record("condition not met in time", sourceLocation: sourceLocation)
        }

        internal static func configuration() throws -> String {
            let key = try PrivateKey.generate(), peer = try PrivateKey.generate()
            var encoded = try SecretBytes(zeroedCount: 44)
            try key.encode(into: &encoded, encoding: .base64)
            let privateKey = encoded.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
            return try """
            [Interface]
            PrivateKey = \(privateKey)
            Address = 192.0.2.2/32
            [Peer]
            PublicKey = \(peer.publicKey().base64)
            Endpoint = vpn.example.invalid:51820
            AllowedIPs = 0.0.0.0/0
            """
        }
    }
#endif
