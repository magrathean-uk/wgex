// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore
import WGEXTesting
import WGEXUI

public enum ExportPreviewFixture {
    public static func makeModel() throws -> ExportModel {
        var input = try Array(FixtureLoader.repository().data("conf/ipv6-dual-stack.conf"))
        let parsed = try parseWgQuick(&input, name: "Home")
        return ExportModel(parsed: consume parsed)
    }
}

public struct ExportPreview: View {
    @State private var model: ExportModel?
    public init() {}
    public var body: some View {
        NavigationStack {
            if let model {
                ExportSheet(model: model)
            } else {
                ProgressView()
            }
        }
        .task { model = try? ExportPreviewFixture.makeModel() }
    }
}

#Preview("Export - light, dark, accessibility") {
    PreviewTraitsMatrix([.light, .dark, .accessibilityText]) { ExportPreview().frame(minHeight: 500) }
}
