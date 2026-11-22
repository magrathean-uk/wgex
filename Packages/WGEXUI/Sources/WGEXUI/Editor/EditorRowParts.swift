// SPDX-License-Identifier: MIT
import SwiftUI

/// A message line of the editor. iOS: a caption in the error colour (or textSecondary for a note); elsewhere the plain
/// text it was, a note in caption and the secondary colour.
package struct EditorMessage: View {
    package enum Tone {
        case error, note
    }

    private let text: String
    private let tone: Tone

    package init(_ text: String, tone: Tone = .error) {
        self.text = text
        self.tone = tone
    }

    package var body: some View {
        #if os(iOS)
            IOSRowCaption(text, tone: tone == .error ? .error : .note)
        #else
            if tone == .note {
                Text(text).font(.caption).foregroundStyle(.secondary)
            } else {
                Text(text)
            }
        #endif
    }
}

/// One server's fields. iOS: rows divided by hairlines inside the server's card row; elsewhere the stack it was.
package struct EditorPeerStack<Content: View>: View {
    @ViewBuilder package let content: Content

    package var body: some View {
        #if os(iOS)
            IOSSubRows { content }
        #else
            VStack(alignment: .leading, spacing: Spacing.medium) { content }
        #endif
    }
}

/// The editor's in-form button looks on iOS (secondary, destructive); other platforms keep their system buttons.
package enum EditorButtonKind {
    case secondary, destructive
}

package extension View {
    @ViewBuilder func editorButton(_ kind: EditorButtonKind) -> some View {
        #if os(iOS)
            switch kind {
            case .secondary: buttonStyle(.iosSecondary)
            case .destructive: buttonStyle(.iosDestructive)
            }
        #else
            self
        #endif
    }
}
