// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Minimal ZIP32 stored-entry writer. No compression, descriptors, filesystem paths or processes.
package enum StoredZIP {
    package struct Entry {
        package let name: String
        package let data: Data
    }

    package static func archive(_ entries: [Entry], maximumBytes: Int) throws(DiagnosticsError) -> Data {
        guard entries.count <= Int(UInt16.max) else { throw .sizeLimit }
        var output = Data()
        var central = Data()
        for entry in entries.sorted(by: { $0.name < $1.name }) {
            let name = Data(entry.name.utf8)
            guard name.count <= Int(UInt16.max), entry.data.count <= maximumBytes,
                  output.count + central.count + entry.data.count + name.count * 2 + 98 <= maximumBytes
            else { throw .sizeLimit }
            let offset = UInt32(output.count)
            let crc = crc32(entry.data)
            output.appendLE(UInt32(0x0403_4B50)); output.appendLE(UInt16(20))
            output.appendLE(UInt16(0x0800)); output.appendLE(UInt16(0))
            output.appendLE(UInt16(0)); output.appendLE(UInt16(33)) // 1980-01-01 00:00:00 DOS time
            output.appendLE(crc); output.appendLE(UInt32(entry.data.count)); output.appendLE(UInt32(entry.data.count))
            output.appendLE(UInt16(name.count)); output.appendLE(UInt16(0)); output.append(name); output.append(entry.data)
            central.appendLE(UInt32(0x0201_4B50)); central.appendLE(UInt16(20)); central.appendLE(UInt16(20))
            central.appendLE(UInt16(0x0800)); central.appendLE(UInt16(0)); central.appendLE(UInt16(0)); central.appendLE(UInt16(33))
            central.appendLE(crc); central.appendLE(UInt32(entry.data.count)); central.appendLE(UInt32(entry.data.count))
            central.appendLE(UInt16(name.count)); central.appendLE(UInt16(0)); central.appendLE(UInt16(0))
            central.appendLE(UInt16(0)); central.appendLE(UInt16(0)); central.appendLE(UInt32(0)); central.appendLE(offset); central
                .append(name)
        }
        guard output.count + central.count + 22 <= maximumBytes else { throw .sizeLimit }
        let centralOffset = UInt32(output.count)
        output.append(central)
        output.appendLE(UInt32(0x0605_4B50)); output.appendLE(UInt16(0)); output.appendLE(UInt16(0))
        output.appendLE(UInt16(entries.count)); output.appendLE(UInt16(entries.count))
        output.appendLE(UInt32(central.count)); output.appendLE(centralOffset); output.appendLE(UInt16(0))
        return output
    }

    package static func crc32(_ data: Data) -> UInt32 {
        CRC32.checksum(data)
    }
}

private extension Data {
    mutating func appendLE(_ value: some FixedWidthInteger) {
        var little = value.littleEndian
        Swift.withUnsafeBytes(of: &little) { append(contentsOf: $0) }
    }
}
