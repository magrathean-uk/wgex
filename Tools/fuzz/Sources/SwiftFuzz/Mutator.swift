// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// SplitMix64 with wrapping arithmetic; deterministic across process and platform runs.
package struct SeededRandom {
    private var state: UInt64
    package init(seed: UInt64) {
        state = seed
    }

    package mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }

    package mutating func index(_ upper: Int) -> Int {
        Int(next() % UInt64(max(1, upper)))
    }
}

package enum Mutator {
    package static let names = ["flip", "insert", "delete", "duplicate-line", "truncate", "control", "crlf", "bom", "key-token"]

    /// Applies `first` and then zero to three further random operations; returns the bytes and the operation chain.
    package static func mutateStack(_ seed: [UInt8], first: Int, fixtureKey: PublicKey, random: inout SeededRandom) -> ([UInt8], String) {
        var operations = [first]
        for _ in 0 ..< random.index(4) {
            operations.append(random.index(names.count))
        }
        var bytes = seed
        for operation in operations {
            bytes = mutate(bytes, operation: operation, fixtureKey: fixtureKey, random: &random)
        }
        return (bytes, operations.map { names[$0] }.joined(separator: "+"))
    }

    package static func mutate(_ seed: [UInt8], operation: Int, fixtureKey: PublicKey, random: inout SeededRandom) -> [UInt8] {
        var bytes = seed
        let offset = random.index(bytes.count)
        switch operation {
        case 0:
            flip(&bytes, at: offset, random: &random)
        case 1:
            bytes.insert(UInt8(truncatingIfNeeded: random.next()), at: offset)
        case 2:
            bytes = Array(bytes[..<offset] + bytes[min(bytes.count, offset + 1)...])
        case 3:
            let start = (bytes[..<offset].lastIndex(of: 10).map { $0 + 1 }) ?? 0
            let end = bytes[offset...].firstIndex(of: 10).map { $0 + 1 } ?? bytes.count
            bytes.insert(contentsOf: Array(bytes[start ..< end]), at: start)
        case 4:
            bytes = Array(bytes.prefix(offset))
        case 5:
            bytes.insert([UInt8(0), 1, 7, 11, 27, 127][random.index(6)], at: offset)
        case 6:
            bytes = bytes.flatMap { $0 == 10 ? [13, 10] : [$0] }
        case 7:
            bytes.insert(contentsOf: [0xEF, 0xBB, 0xBF], at: random.index(2) == 0 ? 0 : offset)
        default:
            // This identity comes from Tests/Fixtures/keys; no invented key token is used.
            let key = fixtureKey.base64
            bytes.insert(contentsOf: Array("\nPrivateKey = \(key)\npreshared_key=\(key)\n".utf8), at: offset)
        }
        return Array(bytes.prefix(256 * 1024 + 1))
    }

    private static func flip(_ bytes: inout [UInt8], at offset: Int, random: inout SeededRandom) {
        guard !bytes.isEmpty else { return }
        bytes[offset] ^= UInt8(1 << random.index(8))
    }

    /// Valid JSON with forbidden member names at varied depths, spelling and duplicate positions.
    /// These controls ensure the rejection oracle sees accepted-schema secret documents too.
    package static func secretControl(_ golden: [UInt8], index: Int) -> [UInt8] {
        let fields = ["private_key", "preshared_key", "PRIVATE_KEY", "private_\\u006bey"]
        let field = "\"\(fields[index % fields.count])\":\"seeded-fuzz-only\""
        let base = String(decoding: golden, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let content = switch (index / fields.count) % 4 {
        case 0: field
        case 1: "\"unknown\":{\(field)}"
        case 2: "\"unknown\":{\(field)},\"unknown\":{}"
        default: "\"unknown\":[{\"nested\":{\(field)}}]"
        }
        return Array(("{" + content + "," + base.dropFirst()).utf8)
    }
}
