// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// M05-T05: an edit or replacement of the running profile keeps on-demand armed across its restart (the official app's
    /// `modify` keeps on-demand), and a superseded key that cannot be deleted once the save has committed never fails the save.
    @MainActor
    @Suite("M05-T05 active edit, on-demand and retirement", .timeLimit(.minutes(1)))
    private struct MacActiveEditOnDemandTests {
        // MARK: On-demand

        @Test func `an edit of the armed running profile restarts it and arms it again`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(armed: true)
            let editor = try await rig.editor(original)
            editor.draft.dns = "10.9.9.9"
            try await editor.save(using: rig.app.saveEditor)
            let restart: [FakeTunnelBackend.Call] = [.install(original.id), .start(original.id, transport: nil)]
            #expect(rig.backend.calls == restart)
            // The start disarmed it on the daemon; the arm follows the start, once.
            #expect(rig.startups.arms.map(\.0) == [original.id])
            #expect(rig.startups.arms.first?.1 == restart)
            #expect(try await rig.app.profileStore.load(original.id).onDemand == MacActiveEditRig.rule)
        }

        @Test func `an edit that removes the rule of the armed running profile restarts it without arming`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(armed: true)
            let editor = try await rig.editor(original)
            editor.draft.dns = "10.9.9.9"
            editor.draft.onDemandForm = MacOnDemandForm(policy: .off)
            try await editor.save(using: rig.app.saveEditor)
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
            #expect(rig.startups.arms.isEmpty)
            #expect(try await rig.app.profileStore.load(original.id).onDemand == .off)
        }

        // MARK: Retirement after the commit

        @Test func `a key that cannot be retired after the save commits still applies the edit`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(fixture: "multi-peer-split")
            let editor = try await rig.editor(original)
            let peer = try #require(editor.draft.peers.first { $0.presharedReference != nil })
            editor.removePresharedKey(peerID: peer.id)
            rig.secrets.refusesDeletion.withLock { $0 = true }
            try await editor.save(using: rig.app.saveEditor)
            let stored = try await rig.app.profileStore.load(original.id)
            #expect(stored.secrets.presharedKeys.count == original.secrets.presharedKeys.count - 1)
            #expect(rig.app.shell.profiles == [stored])
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
            #expect(rig.app.editor == nil)
            #expect(!editor.isDirty)
            try await rig.expectRetiredLater(from: original, kept: stored)
        }

        @Test func `replacing the armed running profile keeps its rule and arms it again after the restart`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(armed: true)
            try await rig.importReplacing(original, connect: false)?.value
            let stored = try await rig.app.profileStore.load(original.id)
            #expect(stored.peers != original.peers)
            #expect(stored.onDemand == MacActiveEditRig.rule)
            let restart: [FakeTunnelBackend.Call] = [.install(original.id), .start(original.id, transport: nil)]
            #expect(rig.backend.calls == restart)
            #expect(rig.startups.arms.map(\.0) == [original.id])
            #expect(rig.startups.arms.first?.1 == restart)
            #expect(rig.app.importErrorMessage == nil)
        }

        @Test func `a key that cannot be retired after a replacement commits still applies the replacement`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(fixture: "multi-peer-split")
            rig.secrets.refusesDeletion.withLock { $0 = true }
            // A file without a pre-shared key: the profile's one is superseded.
            try await rig.importReplacing(original, connect: false, fixture: "ipv6-dual-stack")?.value
            let stored = try await rig.app.profileStore.load(original.id)
            #expect(stored.peers != original.peers)
            #expect(rig.app.shell.profiles == [stored])
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
            #expect(rig.app.importErrorMessage == nil)
            try await rig.expectRetiredLater(from: original, kept: stored)
        }
    }
#endif
