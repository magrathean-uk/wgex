// SPDX-License-Identifier: MIT

/// Validates without constructing String, including secret values and comments.
package enum ConfigurationUTF8 {
    package static func validate(_ raw: UnsafeRawBufferPointer) throws(ConfigParseError) {
        var index = 0; var line = 1
        while index < raw.count {
            let first = raw[index]
            if first < 128 {
                if first == 10 {
                    line += 1
                }
                if isASCIIControl(first) {
                    throw control(line)
                }
                index += 1
            } else {
                let (value, length) = try scalar(raw, at: index)
                if !(index == 0 && value.value == 0xFEFF), isControl(value) {
                    throw control(line)
                }
                index += length
            }
        }
    }

    private static func isASCIIControl(_ byte: UInt8) -> Bool {
        byte < 32 && ![9, 10, 13].contains(byte) || byte == 127
    }

    private static func isControl(_ scalar: UnicodeScalar) -> Bool {
        scalar.properties.generalCategory == .control || scalar.properties.generalCategory == .format
    }

    private static func scalar(_ raw: UnsafeRawBufferPointer, at index: Int) throws(ConfigParseError) -> (UnicodeScalar, Int) {
        let length: Int
        var scalar: UInt32
        switch raw[index] {
        case 0xC2 ... 0xDF: length = 2; scalar = UInt32(raw[index] & 31)
        case 0xE0 ... 0xEF: length = 3; scalar = UInt32(raw[index] & 15)
        case 0xF0 ... 0xF4: length = 4; scalar = UInt32(raw[index] & 7)
        default: throw .invalidUTF8
        }
        guard index + length <= raw.count else { throw .invalidUTF8 }
        for offset in 1 ..< length {
            let byte = raw[index + offset]
            guard (0x80 ... 0xBF).contains(byte) else { throw .invalidUTF8 }
            scalar = scalar << 6 | UInt32(byte & 63)
        }
        guard scalar >= (length == 2 ? 0x80 : length == 3 ? 0x800 : 0x10000), let value = UnicodeScalar(scalar)
        else { throw .invalidUTF8 }
        return (value, length)
    }

    private static func control(_ line: Int) -> ConfigParseError {
        .diagnostics([ConfigDiagnostic(severity: .error, code: .controlCharacter, line: line)])
    }
}
