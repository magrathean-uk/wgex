// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
import WGEXProfileStore
import WGEXTesting
import WGEXUI

@MainActor
internal struct TVAppModelTests {
    @Test(.timeLimit(.minutes(1))) internal func `importing while connected keeps the active profile selected`() async throws {
        let app = TVAppModel(arguments: ["-WGEXFakeBackend"])
        let subscription = Task { await app.run() }
        defer { subscription.cancel() }
        while app.sampledAt == nil {
            await Task.yield()
        }
        try await addFixture(app, name: "First")
        let original = try #require(app.selectedID)
        await app.connect()
        while !TVConnectionState.isRunning(app.status.phase) {
            await Task.yield()
        }
        try await addFixture(app, name: "Second")
        #expect(app.profiles.count == 2)
        #expect(app.selectedID == original)
        #expect(app.selected?.name == "First")
    }

    @Test internal func `editor policy survives storage and settings application`() async throws {
        let app = TVAppModel(arguments: ["-WGEXFakeBackend"])
        try await addFixture(app, name: "Editor")
        let profile = try #require(app.selected)
        await app.openEditor(profile)
        let editor = try #require(app.editor)
        editor.draft.protection.tv.allowLAN = false
        editor.draft.protection.dnsPolicy = .systemDefault
        let edited = try editor.validatedProfile()
        let keys = try editor.makeSecrets()
        try app.stageImport(edited, keys: keys, connect: false, applyDefaults: false)
        #expect(await app.finishStagedImport())
        #expect(app.selected?.protection.tv.allowLAN == false)
        #expect(app.settings.allowLAN == false)
        #expect(app.selected?.protection.dnsPolicy == .systemDefault)
        let stored = try await app.store.load(profile.id)
        #expect(stored.protection.dnsPolicy == .systemDefault)
    }

    @Test(.timeLimit(.minutes(1))) internal func `delete retires only the deleted profiles stored identities`() async throws {
        let app = TVAppModel(arguments: ["-WGEXFakeBackend"])
        try await addFixture(app, name: "Delete")
        let removed = try #require(app.selected)
        let removedIDs = try identities(removed)
        try await addFixture(app, name: "Keep")
        let kept = try #require(app.selected)
        let keptIDs = try identities(kept)
        #expect(removedIDs.count == 2)
        #expect(keptIDs.count == 2)
        await app.openEditor(kept)
        let before = try #require(app.editor)
        let expected = try before.makeSecrets()
        for id in removedIDs + keptIDs {
            #expect(try await app.secrets.exists(id))
        }
        await app.delete(removed)
        #expect(app.message == nil)
        #expect(app.profiles == [kept])
        #expect(try await app.store.list() == [kept])
        for id in removedIDs {
            #expect(try await app.secrets.exists(id) == false)
        }
        for id in keptIDs {
            #expect(try await app.secrets.exists(id))
        }
        app.editor = nil
        try await app.openEditor(app.store.load(kept.id))
        let reopened = try #require(app.editor)
        let actual = try reopened.makeSecrets()
        for reference in expected.references.keys {
            let equal = try actual.withKey(reference) { left in
                try expected.withKey(reference) { left.elementsEqual($0) }
            }
            #expect(equal)
        }
    }

    private func identities(_ profile: TunnelProfile) throws -> [SecretID] {
        try ([profile.secrets.privateKey] + Array(profile.secrets.presharedKeys.values)).map { reference in
            guard case let .daemonStore(id) = reference else { throw ConfigurationError.invalidSecretReference }
            return SecretID(profileID: profile.id, kind: reference == profile.secrets.privateKey ? .privateKey : .presharedKey, id: id)
        }
    }

    private func addFixture(_ app: TVAppModel, name: String) async throws {
        app.paste.text = try FixtureLoader.repository().text("conf/single-peer-full-tunnel.conf")
        app.paste.prepare(existing: app.profiles)
        let review = try #require(app.paste.review)
        review.name = name
        #expect(review.confirm { profile, keys in try app.stageImport(profile, keys: keys, connect: false) })
        #expect(await app.finishStagedImport())
    }
}
