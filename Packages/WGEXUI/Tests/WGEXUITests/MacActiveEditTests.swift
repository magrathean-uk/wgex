// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// M05-T05: editing or replacing the tunnel that is active, as the official app's `TunnelsManager.modify` does. The save
    /// commits first, then a changed tunnel restarts in place (one start of the same profile, never a stop); a save that fails
    /// half-way leaves the old profile running and stored as it was.
    @MainActor
    @Suite("M05-T05 active edit", .timeLimit(.minutes(1)))
    private struct MacActiveEditTests {
        // MARK: Startup options

        @Test func `startup options of the running profile are saved without touching its tunnel`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved()
            let editor = try await rig.editor(original)
            editor.draft.macOptions.autoConnectAtLogin = true
            try await editor.save(using: rig.app.saveEditor)
            #expect(try await rig.app.profileStore.load(original.id).macOptions.autoConnectAtLogin)
            #expect(rig.startups.saved.map(\.1) == [.login])
            #expect(rig.backend.calls.isEmpty)
            #expect(rig.app.shell.activeProfileID == original.id)
            #expect(rig.app.shell.status.phase == .active(Generation(rawValue: 4)))
        }

        @Test func `startup options of a profile while a different tunnel is active keep today's refusal`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(active: UUID())
            let editor = try await rig.editor(original)
            editor.draft.macOptions.autoConnectAtLogin = true
            await #expect(throws: TunnelError.anotherTunnelActive) { try await editor.save(using: rig.app.saveEditor) }
            #expect(try await rig.app.profileStore.load(original.id) == original)
            #expect(rig.startups.saved.isEmpty)
            #expect(rig.backend.calls.isEmpty)
        }

        @Test func `a startup change that fails half way leaves the running profile intact`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved()
            let before = try await rig.privateKey(original)
            rig.app.shell.daemonHooks.stopCurrent = { Issue.record("An edit must never stop the tunnel") }
            let editor = try await rig.editor(original)
            editor.draft.macOptions.autoConnectAtLogin = true
            editor.draft.dns = "10.9.9.9"
            rig.backend.faults.arm("install", error: TunnelError.backendUnavailable)
            await #expect(throws: TunnelError.backendUnavailable) { try await editor.save(using: rig.app.saveEditor) }
            #expect(try await rig.app.profileStore.load(original.id) == original)
            #expect(try await rig.privateKey(original).constantTimeEquals(before))
            #expect(rig.startups.saved.isEmpty)
            #expect(!rig.backend.calls.contains(where: MacActiveEditRig.tunnelCalls))
            #expect(rig.app.shell.profiles == [original])
            #expect(rig.app.shell.activeProfileID == original.id)
            #expect(editor.isDirty)
        }

        // MARK: Editing the running profile

        @Test func `an edit of the running profile is saved then restarted in place without a stop`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved()
            rig.app.shell.daemonHooks.stopCurrent = { Issue.record("An edit must never stop the tunnel") }
            let editor = try await rig.editor(original)
            editor.draft.dns = "10.9.9.9"
            try await editor.save(using: rig.app.saveEditor)
            let stored = try await rig.app.profileStore.load(original.id)
            #expect(stored.interface.dns.map(\.stringRepresentation) == ["10.9.9.9"])
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
            #expect(rig.backend.installedProfiles.first { $0.id == original.id } == stored)
            #expect(rig.startups.arms.isEmpty)
        }

        @Test func `a pre-shared key change restarts and a rename does not`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(fixture: "multi-peer-split")
            let renaming = try await rig.editor(original)
            renaming.draft.name = "Renamed while up"
            try await renaming.save(using: rig.app.saveEditor)
            #expect(rig.backend.calls.isEmpty)
            #expect(try await rig.app.profileStore.load(original.id).name == "Renamed while up")

            let renamed = try await rig.app.profileStore.load(original.id)
            let rekeying = try await rig.editor(renamed)
            let peer = try #require(rekeying.draft.peers.first { $0.presharedReference != nil })
            var replacement = try SecretBytes(zeroedCount: 44)
            try [UInt8](repeating: 7, count: 32).withUnsafeBytes { raw in
                try replacement.withUnsafeMutableBytes { try ByteCodec.encode(raw, into: $0, encoding: .base64) }
            }
            try rekeying.setPresharedKey(replacement, peerID: peer.id)
            try await rekeying.save(using: rig.app.saveEditor)
            #expect(try await rig.app.profileStore.load(original.id).secrets == renamed.secrets)
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
        }

        @Test func `an edit while a different tunnel is active is saved without a restart`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(active: UUID())
            let editor = try await rig.editor(original)
            editor.draft.dns = "10.9.9.9"
            try await editor.save(using: rig.app.saveEditor)
            #expect(try await rig.app.profileStore.load(original.id).interface.dns.map(\.stringRepresentation) == ["10.9.9.9"])
            #expect(rig.backend.calls.isEmpty)
        }

        @Test func `an edit of a stopping tunnel is saved without a restart`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved()
            rig.app.shell.receive(
                MacActiveEditRig.status(active: original.id, phase: .stopping(Generation(rawValue: 4), reason: .userRequested)), at: Date(),
            )
            let editor = try await rig.editor(original)
            editor.draft.dns = "10.9.9.9"
            try await editor.save(using: rig.app.saveEditor)
            #expect(rig.backend.calls.isEmpty)
        }

        // MARK: Replacing by import

        @Test(arguments: [false, true])
        func `replacing the running profile by import saves it and restarts it in place`(connect: Bool) async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved()
            rig.app.shell.daemonHooks.stopCurrent = { Issue.record("A replacement must never stop the tunnel") }
            try await rig.importReplacing(original, connect: connect)?.value
            let stored = try await rig.app.profileStore.load(original.id)
            #expect(stored.peers != original.peers)
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
            #expect(rig.app.importErrorMessage == nil)
            #expect(rig.app.shell.profiles.map(\.id) == [original.id])
        }

        @Test func `a replacement of the running profile that fails half way leaves it running and intact`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved()
            let before = try await rig.privateKey(original)
            rig.backend.faults.arm("install", error: TunnelError.backendUnavailable)
            try await rig.importReplacing(original, connect: true)?.value
            #expect(try await rig.app.profileStore.load(original.id) == original)
            #expect(try await rig.privateKey(original).constantTimeEquals(before))
            #expect(!rig.backend.calls.contains(where: MacActiveEditRig.tunnelCalls))
            #expect(rig.app.importErrorMessage != nil)
            #expect(rig.app.shell.profiles == [original])
            #expect(rig.app.shell.activeProfileID == original.id)
        }

        @Test func `replacing the running profile keeps its startup options and leaves the boot intent alone`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let options = MacProfileOptions(startBeforeLogin: true)
            let original = try await rig.saved(options: options)
            try await rig.importReplacing(original, connect: false)?.value
            let stored = try await rig.app.profileStore.load(original.id)
            #expect(stored.peers != original.peers)
            #expect(stored.macOptions == options)
            #expect(rig.app.shell.profiles.first?.macOptions == options)
            #expect(rig.backend.installedProfiles.first { $0.id == original.id }?.macOptions == options)
            // No startup transaction runs, so the login item and the daemon's boot intent stay as they were.
            #expect(rig.startups.saved.isEmpty)
            #expect(rig.backend.calls == [.install(original.id), .start(original.id, transport: nil)])
        }

        @Test func `replacing a profile while a different tunnel is active keeps today's behaviour`() async throws {
            let rig = MacActiveEditRig()
            defer { try? FileManager.default.removeItem(at: rig.root) }
            let original = try await rig.saved(active: UUID())
            try await rig.importReplacing(original, connect: false)?.value
            #expect(try await rig.app.profileStore.load(original.id).peers != original.peers)
            #expect(rig.backend.calls.isEmpty)
        }
    }
#endif
