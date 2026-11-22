// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore
import WGEXTesting
import WGEXUI

public enum ImportReviewPreviewScenario: String, CaseIterable, Identifiable {
    case clean, errors, warnings, duplicate, keyInUse
    public var id: String {
        rawValue
    }

    public func makeModel() throws -> ImportReviewModel {
        if self == .errors {
            return ImportReviewModel(
                parseError: .diagnostics([ConfigDiagnostic(severity: .error, code: .invalidCIDR, line: 3)]),
                name: "Home",
            )
        }
        var input = try Array(FixtureLoader.repository().data("conf/ipv6-dual-stack.conf"))
        var parsed = try parseWgQuick(&input, name: "Home")
        if self == .warnings {
            parsed.profile.protection.dnsPolicy = .systemDefault
        }
        var existing: [TunnelProfile] = []
        if self == .duplicate {
            existing = [TunnelProfile(name: "Home")]
        }
        if self == .keyInUse {
            var other = parsed.profile; other.name = "Other device"; existing = [other]
        }
        return ImportReviewModel(parsed: consume parsed, existingProfiles: existing)
    }
}

public struct ImportReviewPreview: View {
    @State private var model: ImportReviewModel?
    private let scenario: ImportReviewPreviewScenario
    public init(_ scenario: ImportReviewPreviewScenario) {
        self.scenario = scenario
    }

    public var body: some View {
        NavigationStack {
            if let model {
                ImportReviewScreen(model: model, onImport: { _, _ in }, onImportAndConnect: { _, _ in })
            } else {
                ProgressView()
            }
        }
        .task { model = try? scenario.makeModel() }
    }
}

#Preview("Review - clean, errors, warnings, duplicate, key in use") {
    PreviewTraitsMatrix([.light, .dark, .accessibilityText]) {
        ForEach(ImportReviewPreviewScenario.allCases) { scenario in
            VStack { Text(scenario.rawValue).font(.headline); ImportReviewPreview(scenario).frame(minHeight: 600) }
        }
    }
}
