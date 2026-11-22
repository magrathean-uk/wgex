// SPDX-License-Identifier: MIT

import Foundation
import WGEXUI

/// In-memory ``SecretPasteboard`` for previews and tests; never touches the
/// system pasteboard.
public final class FakeSecretPasteboard: SecretPasteboard {
    /// Increments on every write and clear.
    public private(set) var changeCount = 0
    /// Current text, if any.
    public private(set) var contents: String?
    /// Options of the last write.
    public private(set) var lastOptions: SecretPasteboardOptions?
    /// Number of clears.
    public private(set) var clearCount = 0

    /// Creates an empty pasteboard.
    public init() {}

    /// Records the write.
    public func write(_ text: String, options: SecretPasteboardOptions) -> Int {
        contents = text
        lastOptions = options
        changeCount += 1
        return changeCount
    }

    /// Empties the pasteboard.
    public func clearContents() {
        contents = nil
        clearCount += 1
        changeCount += 1
    }

    /// Simulates another app copying something.
    public func simulateOtherCopy(_ text: String) {
        contents = text
        changeCount += 1
    }
}
