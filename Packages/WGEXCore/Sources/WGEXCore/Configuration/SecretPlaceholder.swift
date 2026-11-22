// SPDX-License-Identifier: MIT
import Foundation

/// Each adjacent delimiter pair is inspected once; malformed literals cannot consume a later opening delimiter.
package enum SecretPlaceholder {
    package static func ranges(in raw: UnsafeRawBufferPointer, uuidOnly: Bool = false) -> [Range<Int>] {
        let prefix = Array("WGEX_SECRET:".utf8)
        var previous: Int?
        var result: [Range<Int>] = []
        for index in raw.indices where raw[index] == 36 {
            defer { previous = index }
            guard let start = previous, index - start > prefix.count,
                  raw[start + 1 ..< start + 1 + prefix.count].elementsEqual(prefix) else { continue }
            let id = raw[start + 1 + prefix.count ..< index]
            if isUUID(id) || (!uuidOnly && isBase64(id)) {
                result.append(start ..< index + 1)
            }
        }
        return result
    }

    package static func candidates(in raw: UnsafeRawBufferPointer) -> Set<String> {
        Set(ranges(in: raw, uuidOnly: true).map { String(decoding: raw[$0], as: UTF8.self) })
    }

    private static func isUUID(_ bytes: Slice<UnsafeRawBufferPointer>) -> Bool {
        guard bytes.count == 36 else { return false }
        return bytes.enumerated().allSatisfy { offset, byte in
            if [8, 13, 18, 23].contains(offset) {
                return byte == 45
            }
            return (48 ... 57).contains(byte) || (65 ... 70).contains(byte) || (97 ... 102).contains(byte)
        }
    }

    private static func isBase64(_ bytes: Slice<UnsafeRawBufferPointer>) -> Bool {
        guard !bytes.isEmpty, bytes.count.isMultiple(of: 4) else { return false }
        var padding = 0
        for byte in bytes {
            if byte == 61 {
                padding += 1; if padding > 2 {
                    return false
                }
            } else if padding > 0 || !((65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 43 || byte == 47)
            {
                return false
            }
        }
        return true
    }
}
