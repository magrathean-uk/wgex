// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI

    // SwiftFormat does not recognise public declarations expanded by @Entry.
    // swiftformat:disable docComments
    public extension EnvironmentValues {
        /// The window's Import from File… action (the file picker, then Review Tunnel). The app sets it; without it the empty
        /// page's button opens Add a Tunnel instead.
        @Entry var macImportFromFile: MacWindowAction? = nil
    }

    // swiftformat:enable docComments

    /// A window-level action handed down the environment. Every instance compares equal: the action never changes what a view
    /// shows, so replacing it must not invalidate the views that read it.
    public struct MacWindowAction: Equatable, Sendable {
        private let perform: @MainActor @Sendable () -> Void

        public init(_ perform: @escaping @MainActor @Sendable () -> Void) {
            self.perform = perform
        }

        public func callAsFunction() {
            perform()
        }

        public static func == (_: Self, _: Self) -> Bool {
            true
        }
    }

    /// The main window's detail column when no tunnel exists (SPEC 6.5), centred. `MacMainWindowView` hosts it with its own Add
    /// and Paste actions; the whole window takes dropped files.
    package struct MacEmptyTunnelsView: View {
        package let model: MacShellModel
        package let addProfile: () -> Void
        package let paste: () -> Void
        @Environment(\.macImportFromFile) private var importFromFile

        package init(model: MacShellModel, addProfile: @escaping () -> Void, paste: @escaping () -> Void) {
            self.model = model; self.addProfile = addProfile; self.paste = paste
        }

        package var body: some View {
            VStack(spacing: 10) {
                Text(MacStrings.noTunnelsTitle).font(MacDesign.pageTitle).lineLimit(1)
                Text(MacStrings.addAConfigurationMadeForThisMac).foregroundStyle(MacDesign.label2)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button(MacStrings.importFromFile) {
                        if let importFromFile {
                            importFromFile()
                        } else {
                            addProfile()
                        }
                    }
                    .wgexControl(.main, "importFromFile", label: MacStrings.importFromFile)
                    .buttonStyle(.macPrimary).keyboardShortcut(.defaultAction).lineLimit(1)
                    Button(MacStrings.pasteFromClipboard, action: paste)
                        .wgexControl(.main, "pasteConfiguration", label: MacStrings.pasteFromClipboard)
                        .lineLimit(1)
                }
                .padding(.top, 6)
                Text(MacStrings.orDropAConfFileHere).font(MacDesign.small).foregroundStyle(MacDesign.label2).lineLimit(1)
                    .wgexAX(.main, "dropHint", label: MacStrings.orDropAConfFileHere)
            }
            .buttonStyle(.macSecondary)
            .padding(24)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(MacDesign.pageBackground)
        }
    }
#endif
