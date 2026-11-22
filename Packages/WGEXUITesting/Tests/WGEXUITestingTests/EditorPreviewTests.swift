// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI
import WGEXUITesting

private struct EditorPreviewTests {
    @Test(arguments: EditorPreviewScenario.allCases)
    func `editor fixtures show the named validation state`(_ scenario: EditorPreviewScenario) throws {
        let model = try scenario.makeModel()
        #expect(model.canSave == (scenario == .valid || scenario == .warnings))
        if scenario == .warnings {
            #expect(model.diagnostics.contains { $0.diagnostic.severity == .warning })
        }
    }

    @Test(arguments: ImportReviewPreviewScenario.allCases)
    func `review fixtures expose each promised case`(_ scenario: ImportReviewPreviewScenario) throws {
        let model = try scenario.makeModel()
        #expect(model.canImport == (scenario != .errors))
        if scenario == .duplicate {
            #expect(model.duplicates.contains { $0.sameName })
        }
        if scenario == .keyInUse {
            #expect(model.keyInUseElsewhere)
        }
        if scenario == .warnings {
            #expect(!model.warnings.isEmpty)
        }
    }

    @Test
    func `export fixture offers only placeholder text before confirmation`() throws {
        let model = try ExportPreviewFixture.makeModel()
        #expect(model.shareableText.contains("$WGEX_SECRET:"))
        #expect(model.pendingPurpose == nil)
    }
}
