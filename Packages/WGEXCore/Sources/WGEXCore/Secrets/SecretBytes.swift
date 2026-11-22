// SPDX-License-Identifier: MIT
import Foundation

/// Key material in a page-aligned `mmap` region, `mlock`ed where the system
/// allows it and wiped with `memset_s` in `deinit` (02 §3, ADR-008).
///
/// It is neither `Codable` nor `CustomStringConvertible`, and it is
/// `~Copyable`, so every copy is explicit. Copies made by Foundation, XPC or the
/// Go heap are transient and not wiped: the contract is "minimise and bound".
public struct SecretBytes: ~Copyable, @unchecked Sendable {
    /// Report delivered to ``wipeObserver`` after a buffer is wiped. It carries
    /// sizes and a zero check, never key material.
    public struct WipeReport: Sendable, Hashable {
        /// Logical length of the wiped buffer.
        public let byteCount: Int
        /// Length of the wiped mapping (whole pages).
        public let mappedByteCount: Int
        /// True when every byte of the mapping read back as zero after the wipe.
        public let isZeroed: Bool
    }

    /// Largest buffer accepted (1 MiB, the XPC envelope bound).
    public static let maximumCount = 1 << 20

    /// Test hook: while bound with `$wipeObserver.withValue`, every buffer
    /// destroyed in that task reports its wipe. Production code never binds it.
    @TaskLocal package static var wipeObserver: (@Sendable (WipeReport) -> Void)?

    /// Allocation seam for deterministic failure and lifetime tests. Callbacks never receive secret bytes.
    package struct Allocator: Sendable {
        package var allocate: @Sendable (Int) -> UnsafeMutableRawPointer?
        package var lock: @Sendable (UnsafeMutableRawPointer, Int) -> Bool
        package var didWipe: (@Sendable (WipeReport) -> Void)?

        package init(
            allocate: @escaping @Sendable (Int) -> UnsafeMutableRawPointer?,
            lock: @escaping @Sendable (UnsafeMutableRawPointer, Int) -> Bool,
            didWipe: (@Sendable (WipeReport) -> Void)?,
        ) {
            self.allocate = allocate; self.lock = lock; self.didWipe = didWipe
        }

        package static let system = Allocator(
            allocate: { mmap(nil, $0, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) },
            lock: { mlock($0, $1) == 0 },
            didWipe: nil,
        )
    }

    @TaskLocal package static var allocator: Allocator = .system
    private let observer: (@Sendable (WipeReport) -> Void)?
    private let allocatorObserver: (@Sendable (WipeReport) -> Void)?

    /// Logical length in bytes.
    public let count: Int
    /// True when `mlock` succeeded; false means the pages may be swapped.
    public let isLocked: Bool

    // `@unchecked Sendable` is sound because the value is uniquely owned
    // (`~Copyable`): the mapping is never shared between two owners.
    private let base: UnsafeMutableRawPointer
    private let mappedCount: Int

    /// Allocates `count` zeroed bytes.
    public init(zeroedCount count: Int) throws(SecretBytesError) {
        guard count >= 0, count <= Self.maximumCount else {
            throw .invalidLength(count)
        }
        let page = Int(getpagesize())
        let mapped = max(page, (count + page - 1) / page * page)
        guard let region = Self.allocator.allocate(mapped),
              region != UnsafeMutableRawPointer(bitPattern: -1)
        else {
            throw .allocationFailed(errno)
        }
        base = region
        mappedCount = mapped
        self.count = count
        isLocked = Self.allocator.lock(region, mapped)
        observer = Self.wipeObserver
        allocatorObserver = Self.allocator.didWipe
    }

    /// Copies `source` into a new buffer. The caller remains responsible for wiping `source`.
    public init(copying source: UnsafeRawBufferPointer) throws(SecretBytesError) {
        try self.init(zeroedCount: source.count)
        if let from = source.baseAddress, source.count > 0 {
            base.copyMemory(from: from, byteCount: source.count)
        }
    }

    /// Copies `range` of `other` into a new buffer.
    public init(copying other: borrowing SecretBytes, range: Range<Int>) throws(SecretBytesError) {
        guard range.lowerBound >= 0, range.upperBound <= other.count else {
            throw .outOfBounds
        }
        try self.init(zeroedCount: range.count)
        let destination = base
        other.withUnsafeBytes { source in
            if let from = source.baseAddress, !range.isEmpty {
                destination.copyMemory(from: from + range.lowerBound, byteCount: range.count)
            }
        }
    }

    /// Explicit copy of another buffer (02 §3 `init(parsing:)`).
    public init(parsing other: borrowing SecretBytes) throws(SecretBytesError) {
        try self.init(copying: other, range: 0 ..< other.count)
    }

    /// Copies `data` into a new buffer, then overwrites `data` with zeros.
    /// Best effort: storage that `data` shares with another value is copied
    /// on write and that other copy is not wiped.
    public init(wiping data: inout Data) throws(SecretBytesError) {
        defer {
            data.withUnsafeMutableBytes { raw in
                if let start = raw.baseAddress {
                    _ = memset_s(start, raw.count, 0, raw.count)
                }
            }
        }
        self = try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) throws(SecretBytesError) -> SecretBytes in
            try SecretBytes(copying: raw)
        }
    }

    deinit {
        _ = memset_s(base, mappedCount, 0, mappedCount)
        if observer != nil || allocatorObserver != nil {
            let zeroed = UnsafeRawBufferPointer(start: base, count: mappedCount).allSatisfy { $0 == 0 }
            let report = WipeReport(byteCount: count, mappedByteCount: mappedCount, isZeroed: zeroed)
            observer?(report)
            allocatorObserver?(report)
        }
        if isLocked {
            munlock(base, mappedCount)
        }
        munmap(base, mappedCount)
    }

    /// Calls `body` with a read-only view of the bytes. Do not let the pointer escape.
    public func withUnsafeBytes<Result, Failure: Error>(
        _ body: (UnsafeRawBufferPointer) throws(Failure) -> Result,
    ) throws(Failure) -> Result {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// Calls `body` with a writable view of the bytes. Do not let the pointer escape.
    public mutating func withUnsafeMutableBytes<Result, Failure: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(Failure) -> Result,
    ) throws(Failure) -> Result {
        try body(UnsafeMutableRawBufferPointer(start: base, count: count))
    }

    /// Copies all bytes into `destination`, which must have the same length (02 §3).
    public func encode(into destination: inout SecretBytes) throws(SecretBytesError) {
        guard destination.count == count else {
            throw .outOfBounds
        }
        try copyBytes(into: &destination, at: 0)
    }

    /// Copies all bytes into `destination` starting at `offset`.
    public func copyBytes(into destination: inout SecretBytes, at offset: Int) throws(SecretBytesError) {
        guard offset >= 0, offset <= destination.count, count <= destination.count - offset else {
            throw .outOfBounds
        }
        let source = base
        let length = count
        destination.withUnsafeMutableBytes { target in
            if let start = target.baseAddress, length > 0 {
                (start + offset).copyMemory(from: source, byteCount: length)
            }
        }
    }

    /// Length-checked comparison whose running time does not depend on where the bytes differ.
    public func constantTimeEquals(_ other: borrowing SecretBytes) -> Bool {
        guard count == other.count else { return false }
        guard count > 0 else { return true }
        let mine = base
        let length = count
        return other.withUnsafeBytes { theirs in
            guard let address = theirs.baseAddress else { return false }
            return timingsafe_bcmp(mine, address, length) == 0
        }
    }
}
