// SPDX-License-Identifier: MIT

/// ZIP/IEEE CRC-32 shared by archive import and diagnostics export.
public enum CRC32 {
    private static let table: [UInt32] = (0 ..< 256).map { index in
        var value = UInt32(index)
        for _ in 0 ..< 8 {
            value = (value >> 1) ^ (value & 1 == 0 ? 0 : 0xEDB8_8320)
        }
        return value
    }

    /// Computes the checksum of borrowed bytes without retaining them.
    public static func checksum(_ bytes: some Sequence<UInt8>) -> UInt32 {
        var crc = UInt32.max
        for byte in bytes {
            crc = (crc >> 8) ^ table[Int((crc ^ UInt32(byte)) & 255)]
        }
        return crc ^ UInt32.max
    }
}
