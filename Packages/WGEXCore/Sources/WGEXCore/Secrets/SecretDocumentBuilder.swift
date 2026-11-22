// SPDX-License-Identifier: MIT
import Foundation

/// Only public text and references enter this builder. Keys are written straight to wiped storage.
package struct SecretDocumentBuilder {
    private enum Piece {
        case text(String)
        case key(SecretRef, KeyEncoding)
    }

    private var pieces: [Piece] = []

    package init() {}

    package mutating func append(_ text: String) {
        pieces.append(.text(text))
    }

    package mutating func appendKey(_ reference: SecretRef, encoding: KeyEncoding) {
        pieces.append(.key(reference, encoding))
    }

    package func finish(secrets: borrowing ParsedSecrets) throws -> SecretBytes {
        let count = pieces.reduce(0) { total, piece in
            switch piece {
            case let .text(text): total + text.utf8.count
            case let .key(_, encoding): total + ByteCodec.encodedCount(32, encoding: encoding)
            }
        }
        var bytes = try SecretBytes(zeroedCount: count)
        var cursor = 0
        try bytes.withUnsafeMutableBytes { output in
            for piece in pieces {
                switch piece {
                case let .text(text):
                    for byte in text.utf8 {
                        output[cursor] = byte; cursor += 1
                    }
                case let .key(reference, encoding):
                    let length = ByteCodec.encodedCount(32, encoding: encoding)
                    try secrets.withKey(reference) { key in
                        try ByteCodec.encode(
                            key,
                            into: UnsafeMutableRawBufferPointer(rebasing: output[cursor ..< cursor + length]),
                            encoding: encoding,
                        )
                    }
                    cursor += length
                }
            }
        }
        return bytes
    }
}
