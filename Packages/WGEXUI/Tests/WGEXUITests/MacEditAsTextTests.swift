// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXUI

    /// SPEC 6.3 and E7: Edit as Text and the click-to-reveal key rows of the Mac Edit sheet.
    @MainActor
    private struct MacEditAsTextTests {
        private func editor(_ fixture: String = "multi-peer-split") throws -> ProfileEditorModel {
            let parsed = try EditorFixtures.parsed(fixture)
            return try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets, allowsIncomplete: true)
        }

        @Test(arguments: ["multi-peer-split", "ipv6-dual-stack", "single-peer-full-tunnel"])
        func `form to text to form keeps every field and key`(_ fixture: String) throws {
            let model = try editor(fixture)
            model.draft.name = "Renamed"
            model.draft.macOptions.autoConnectAtLogin = true
            model.draft.protection.ipv6Policy = .blockOutside
            let draft = model.draft
            let before = try model.validatedProfile()
            let privateKey = model.privateKeyForField()
            let presharedKeys = model.draft.peers.map { model.presharedKeyForField(peerID: $0.id) }
            #expect(model.canEditAsText)
            let text = try model.configurationTextForEditing()
            #expect(text.contains("[Interface]"))
            #expect(try EditorFixtures.containsSecret(text), "The text view carries the keys")
            var bytes = Array(text.utf8)
            let warnings = try model.applyConfigurationText(&bytes)
            #expect(warnings.isEmpty)
            #expect(bytes.allSatisfy { $0 == 0 }, "The parsed buffer is wiped")
            #expect(model.draft == draft, "Name, servers, policy and start-up survive the round trip")
            let after = try model.validatedProfile()
            #expect(after.interface == before.interface)
            #expect(after.peers == before.peers)
            #expect(after.secrets == before.secrets)
            #expect(model.privateKeyForField() == privateKey)
            #expect(model.draft.peers.map { model.presharedKeyForField(peerID: $0.id) } == presharedKeys)
        }

        @Test func `text that does not parse changes nothing and reports its problem`() throws {
            let model = try editor()
            let draft = model.draft
            let key = model.privateKeyForField()
            var bytes = Array("[Interface]\nAddress = 10.0.0.2/32\n".utf8)
            let error = #expect(throws: ConfigParseError.self) { try model.applyConfigurationText(&bytes) }
            let lines = try MacTextProblems.lines(#require(error))
            #expect(lines.first == MacStrings.textIsNotAConfiguration)
            #expect(lines.count > 1)
            #expect(model.draft == draft)
            #expect(model.privateKeyForField() == key)
        }

        @Test func `text with only an interface and a private key applies under the empty-tunnel rule`() throws {
            let model = ProfileEditorModel(allowsIncomplete: true)
            model.generateKeypair()
            model.draft.name = "Text only"
            let text = try model.configurationTextForEditing()
            #expect(!text.contains("[Peer]"))
            var bytes = Array(text.utf8)
            try model.applyConfigurationText(&bytes)
            #expect(model.canSave, "A name and a key are enough (DEC-088)")
            #expect(model.diagnostics.contains { $0.diagnostic.message == MacStrings.addAServerBeforeActivating })
        }

        @Test func `removed commands come back as plain words`() throws {
            let model = try editor()
            var text = try model.configurationTextForEditing()
            text = text.replacingOccurrences(of: "[Interface]\n", with: "[Interface]\nPostUp = echo up\n")
            var bytes = Array(text.utf8)
            let warnings = try model.applyConfigurationText(&bytes)
            #expect(MacTunnelProblems.lines(warnings) == [MacStrings.commandsWereRemoved])
        }

        @Test func `a form field that does not parse keeps the text view closed`() throws {
            let model = try editor()
            model.draft.addresses = "not an address"
            #expect(!model.canEditAsText)
        }

        @Test func `the key rows load the key only on reveal and never label it`() throws {
            let row = try source("MacPrivateKeyRow.swift")
            #expect(row.contains("SecretRevealState.mask"), "Hidden keys show fixed-length dots")
            #expect(row.contains("label: MacStrings.hidden(title)"))
            #expect(row.contains("NSApplication.didResignActiveNotification"))
            #expect(row.contains(".onDisappear { hide() }"))
            #expect(row.contains(".privacySensitive()"))
            #expect(MacStrings.hidden(MacStrings.privateKey) == "Private key, hidden")
            let sheet = try source("MacTunnelEditSheet.swift")
            #expect(sheet.contains(".onDisappear { session.close() }"))
            #expect(sheet.contains(".macOnWindowLeave { session.leave(model) }"))
            #expect(sheet.contains("resetToken: model.keyResetRevision"))
        }

        // MARK: Repair round (REV-M07-T04 and adversarial pass 1)

        private func source(_ name: String) throws -> String {
            try String(
                contentsOf: URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                    .appending(path: "Sources/WGEXUI/Screens/Mac/\(name)"),
                encoding: .utf8,
            )
        }

        /// Review 1 and A2: the row keeps no buffer of its own, so it can never show one key while the model holds another,
        /// and a bad paste never leaves an error the user cannot clear.
        @Test func `a pasted key reaches the model only when it parses, and pasting the original back restores it`() throws {
            let model = try editor()
            let original = try #require(model.privateKeyForField())
            let other = ProfileEditorModel()
            other.generateKeypair()
            let replacement = try #require(other.privateKeyForField())
            #expect(!MacKeyPaste.commit(original + "x", using: { try model.setPrivateKey($0) }))
            #expect(!MacKeyPaste.commit("not a key", using: { try model.setPrivateKey($0) }))
            #expect(model.keyErrors.isEmpty && model.canSave && model.privateKeyForField() == original)
            #expect(MacKeyPaste.commit(replacement + "\n", using: { try model.setPrivateKey($0) }))
            #expect(model.privateKeyForField() == replacement)
            #expect(MacKeyPaste.commit(original, using: { try model.setPrivateKey($0) }))
            #expect(model.privateKeyForField() == original)
            #expect(!model.isDirty, "Back to the original key: nothing left to save")
            let peer = try #require(model.draft.peers.first { model.hasPresharedKey($0.id) })
            let preshared = try #require(model.presharedKeyForField(peerID: peer.id))
            #expect(!MacKeyPaste.commit("bad", using: { try model.setPresharedKey($0, peerID: peer.id) }))
            #expect(model.keyErrors.isEmpty)
            #expect(MacKeyPaste.commit(replacement, using: { try model.setPresharedKey($0, peerID: peer.id) }))
            #expect(MacKeyPaste.commit(preshared, using: { try model.setPresharedKey($0, peerID: peer.id) }))
            #expect(model.presharedKeyForField(peerID: peer.id) == preshared)
            let row = try source("MacPrivateKeyRow.swift")
            #expect(!row.contains("TextField("), "No editable buffer: the revealed key is the model's")
            #expect(!row.contains("@State private var text"))
            #expect(row.contains("Text(load() ?? MacStrings.noPresharedKey)"))
        }

        /// Review 2 and A3: a second click, or Space, hides the revealed key; so do the window resigning key or being minimised.
        @Test func `the revealed key hides on a second click, Space, and when its window goes away`() throws {
            let row = try source("MacPrivateKeyRow.swift")
            let revealed = try #require(row.components(separatedBy: "private var revealedKey: some View {").last)
                .components(separatedBy: "/// The row's identifier")[0]
            #expect(revealed.contains(".onTapGesture { hide() }"))
            #expect(revealed.contains(".onKeyPress(.space)"))
            #expect(revealed.contains(".onPasteCommand(of: [.plainText])"))
            #expect(row.contains(".macOnWindowLeave { hide() }"))
            for name in ["didResignKeyNotification", "willMiniaturizeNotification", "willCloseNotification"] {
                #expect(row.contains("NSWindow.\(name)"))
            }
            #expect(MacStrings.keyRowHelp == "Click to hide. Paste a key to replace it.")
        }

        /// A4: changes made outside the row (Generate Key Pair, Clear Preshared Key, Remove Server, Edit as Text) hide a
        /// revealed row; the row's own paste does not.
        @Test func `key changes made elsewhere move the reset token and a paste does not`() throws {
            let model = try editor()
            let row = try source("MacPrivateKeyRow.swift")
            #expect(row.contains(".onChange(of: resetToken) { hide() }"))
            var token = model.keyResetRevision
            let other = ProfileEditorModel()
            other.generateKeypair()
            let replacement = try #require(other.privateKeyForField())
            #expect(MacKeyPaste.commit(replacement, using: { try model.setPrivateKey($0) }))
            #expect(model.keyResetRevision == token)
            model.generateKeypair()
            #expect(model.keyResetRevision > token)
            token = model.keyResetRevision
            let peer = try #require(model.draft.peers.first { model.hasPresharedKey($0.id) })
            model.removePresharedKey(peerID: peer.id)
            #expect(model.keyResetRevision > token)
            token = model.keyResetRevision
            var bytes = try Array(model.configurationTextForEditing().utf8)
            try model.applyConfigurationText(&bytes)
            #expect(model.keyResetRevision > token)
            token = model.keyResetRevision
            model.removePeer(id: peer.id)
            #expect(model.keyResetRevision > token)
        }

        /// A1: text the app must drop on deactivation is announced, and stays announced in the form.
        @Test func `text dropped when the app or window goes away is announced, text that parses is kept`() throws {
            let model = try editor()
            let draft = model.draft
            var session = MacTextSession()
            try session.open(model)
            let peerKey = try #require(model.draft.peers.first?.publicKey)
            session.text = session.text.replacingOccurrences(of: "PublicKey = \(peerKey)", with: "PublicKey = \(peerKey.prefix(10))")
                .replacingOccurrences(of: "[Interface]\n", with: "[Interface]\nDNS = 10.9.9.9\n")
            #expect(session.isEdited)
            session.leave(model)
            #expect(!session.isActive && session.text.isEmpty && !session.isEdited)
            #expect(session.notice.first == MacStrings.textChangesDiscarded)
            #expect(session.notice.count > 1, "The reason follows")
            #expect(model.draft == draft, "Unparsed text changes nothing")
            try session.open(model)
            #expect(session.notice.isEmpty)
            session.text = session.text.replacingOccurrences(of: "[Interface]\n", with: "[Interface]\nPostUp = echo up\n")
            session.leave(model)
            #expect(session.notice == [MacStrings.commandsWereRemoved], "Applied text keeps its warnings")
            try session.open(model)
            session.text = "[Interface]\n"
            let returned = session.returnToForm(model)
            #expect(!returned)
            #expect(session.isActive, "Edit as Form keeps the text view for text that does not parse")
            #expect(session.problems.first == MacStrings.textIsNotAConfiguration)
            session.close()
            #expect(session.text.isEmpty)
        }
    }
#endif
