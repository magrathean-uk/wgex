// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore
import WGEXTesting
import WGEXUI

public enum EditorPreviewScenario: String, CaseIterable, Identifiable {
    case empty, valid, errors, warnings
    public var id: String {
        rawValue
    }

    public func makeModel() throws -> ProfileEditorModel {
        if self == .empty {
            return ProfileEditorModel()
        }
        var input = try Array(FixtureLoader.repository().data("conf/ipv6-dual-stack.conf"))
        let parsed = try parseWgQuick(&input, name: "Home")
        let model = try ProfileEditorModel(
            profile: parsed.profile,
            secrets: parsed.secrets,
            featureFlags: FeatureFlags(relayTransports: true),
        )
        if self == .errors {
            model.draft.mtu = "9001"; model.draft.peers[0].endpoint = "vpn.example.test:0"
        }
        if self == .warnings {
            model.draft.protection.dnsPolicy = .systemDefault
        }
        return model
    }
}

/// The editor with long values, for the pictures of the whole form: a 128-character name, a 120-character endpoint, two
/// servers, on-demand on Wi-Fi for three named networks only, and two exclusions.
public enum EditorLongValuesFixture {
    public static func makeModel() throws -> ProfileEditorModel {
        let model = try EditorPreviewScenario.valid.makeModel()
        model.draft.name = String(String(repeating: "Office tunnel through the long way round ", count: 4).prefix(128))
        // 120 characters, in words (a long unbroken run reads as key material to the public-field check).
        model.draft.peers[0].endpoint =
            "gateway-001.eu-west-2.office-network.long-domain-name-for-testing.vpn-gateways.internal.branch-office.example.test:51820"
        model.addPeer()
        let second = model.draft.peers.count - 1
        let keyFile = try String(decoding: FixtureLoader.repository().data("keys/client2.pub"), as: UTF8.self)
        // The file's last line is the key; the lines before it are comments.
        let key = keyFile.split(whereSeparator: \.isNewline).last { !$0.hasPrefix("#") && !$0.isEmpty }
        model.draft.peers[second].publicKey = key.map(String.init) ?? ""
        model.draft.peers[second].endpoint = "backup.example.test:51820"
        model.draft.peers[second].allowedIPs = AllowedIPsModel(text: "10.20.0.0/16, 192.168.40.0/24")
        model.draft.peers[second].keepalive = "25"
        let names = ["Home", "Office Wi-Fi 5 GHz", "Corner cafe guest network"]
        // The iOS form first: a change to it resets the Mac form to the policy it writes.
        model.iosOnDemand = IOSOnDemandForm(wifi: true, match: .only, networks: names.map { .init(name: $0) })
        model.draft.onDemandForm = MacOnDemandForm(wifi: true, match: .only, networks: names.map { .init(name: $0) })
        model.draft.exclusions = ["198.51.100.0/24", "10.77.0.128/25"]
        return model
    }
}

/// Each draft state can be viewed under every shared accessibility/appearance trait.
public struct EditorPreview: View {
    @State private var model: ProfileEditorModel?
    private let scenario: EditorPreviewScenario
    public init(_ scenario: EditorPreviewScenario) {
        self.scenario = scenario
    }

    public var body: some View {
        NavigationStack {
            if let model {
                ProfileEditorForm(model: model, onSave: { _, _ in }, onCancel: {})
            } else {
                ProgressView()
            }
        }
        .task { model = try? scenario.makeModel() }
    }
}

#Preview("Editor - empty, valid, errors, warnings; all traits") {
    PreviewTraitsMatrix {
        ForEach(EditorPreviewScenario.allCases) { scenario in
            VStack { Text(scenario.rawValue).font(.headline); EditorPreview(scenario).frame(minHeight: 700) }
        }
    }
}

#Preview("Editor - light") { EditorPreview(.valid).previewTraits(.light) }
#Preview("Editor - dark") { EditorPreview(.valid).previewTraits(.dark) }
#Preview("Editor - accessibility") { EditorPreview(.errors).previewTraits(.accessibilityText) }
