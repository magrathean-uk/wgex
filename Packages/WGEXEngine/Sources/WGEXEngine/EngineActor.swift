// SPDX-License-Identifier: MIT

#if WGEX_ENGINE_TEST_SUPPORT
    import CWGEXEngineTest
#else
    import CWGEXEngine
#endif
import Foundation
import Synchronization
import WGEXCore
import WGEXEngineInterface

/// Serialises the C ABI and owns its callback registration through the final destroy.
public actor EngineActor: EngineControlling {
    public nonisolated let logs: AsyncStream<EngineLogLine>
    public nonisolated let events: AsyncStream<EngineEvent>
    /// Bounded loss notifications, separate because EngineEvent has no diagnostics case.
    public nonisolated let callbackDrops: AsyncStream<EngineCallbackDrops>

    private let callbacks: CallbackBox
    private var handle: Int64
    private var generation: UInt64 = 0
    private static let processLimits = Mutex<EngineConfiguration.ProcessLimits?>(nil)

    public init(configuration: EngineConfiguration) throws(EngineError) {
        try Self.validateABIVersion(wgex_abi_version())
        let box = CallbackBox()
        let created = try Self.create(configuration, callbacks: box)
        handle = created
        callbacks = box
        logs = box.logs
        events = box.events
        callbackDrops = box.drops
    }

    /// Checks compatibility before any engine or callback lifetime is created.
    package nonisolated static func validateABIVersion(_ version: Int32) throws(EngineError) {
        guard version == WGEX_ABI_VERSION else { throw .abiMismatch }
    }

    /// Test seam: adopts an existing netstack handle registered with this box. Ownership
    /// transfers to this actor; the pair's later idempotent destroy may see it already gone.
    package init(adopting handle: Int64, callbacks: CallbackBox) {
        self.handle = handle
        self.callbacks = callbacks
        logs = callbacks.logs
        events = callbacks.events
        callbackDrops = callbacks.drops
    }

    deinit {
        if handle > 0 {
            // No callbacks call into this actor; destroy synchronously drains their box.
            _ = wgex_destroy(handle)
        }
        callbacks.finish()
    }

    public func setConfiguration(_ uapi: borrowing UAPIDocument) throws(EngineError) {
        try ensureAlive()
        // Borrow the locked mapping for this call only. C copies what it needs before returning.
        let code = unsafe uapi.bytes.withUnsafeBytes { bytes in
            unsafe wgex_set_config(handle, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count)
        }
        try Self.check(code)
        generation &+= 1
    }

    public func updateEndpoints(_ updates: [PublicKey: Endpoint]) throws(EngineError) {
        try ensureAlive()
        guard !updates.isEmpty else { return }
        do {
            let document = try UAPIEncoder.endpointUpdates(updates)
            // Only public endpoint data; still borrow and let UAPIDocument wipe its buffer.
            let code = unsafe document.bytes.withUnsafeBytes { bytes in
                unsafe wgex_update_endpoints(handle, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count)
            }
            try Self.check(code)
        } catch let error as EngineError { throw error }
        catch { throw .invalidArgument }
    }

    public func up() throws(EngineError) {
        try ensureAlive()
        try Self.check(wgex_up(handle))
    }

    public func down() throws(EngineError) {
        try ensureAlive()
        try Self.check(wgex_down(handle))
    }

    public func bumpSockets(v4: UInt32?, v6: UInt32?) throws(EngineError) {
        try ensureAlive()
        try Self.check(wgex_bump_sockets(handle, Self.index(v4), Self.index(v6)))
    }

    public func setTransport(_ spec: TransportSpec) throws(EngineError) {
        try ensureAlive()
        let json = Self.transport(spec)
        // withCString keeps the NUL-terminated public transport document valid through C.
        let code = json.withCString { unsafe wgex_set_transport(handle, $0, json.utf8.count) }
        try Self.check(code)
    }

    public func forceHandshake() throws(EngineError) {
        try ensureAlive()
        try Self.check(wgex_force_handshake(handle))
    }

    public func statistics() throws(EngineError) -> TunnelStatistics {
        try ensureAlive()
        guard let pointer = unsafe wgex_public_stats_json(handle) else { throw .internal }
        // The ABI returns an owned NUL-terminated allocation. Copy public bytes, then free once.
        defer { unsafe wgex_free(pointer) }
        let count = unsafe strlen(pointer)
        let bytes = unsafe Array(UnsafeRawBufferPointer(start: pointer, count: count))
        do { return try UAPIStatsDecoder.decode(bytes, generation: generation) }
        catch { throw .internal } // Includes the recursive secret-key guard; never expose input in errors.
    }

    public func shutdown() async {
        guard handle > 0 else { return }
        let owned = handle
        handle = 0
        // No suspension before destroy returns; the callback box outlives its drain.
        _ = wgex_destroy(owned)
        callbacks.finish()
    }

    private func ensureAlive() throws(EngineError) {
        guard handle > 0 else { throw .invalidHandle }
    }

    private static func check(_ code: Int32) throws(EngineError) {
        if let error = EngineError(code: code) {
            throw error
        }
    }

    private static func index(_ value: UInt32?) throws(EngineError) -> Int32 {
        guard let result = Int32(exactly: value ?? 0) else { throw .invalidArgument }
        return result
    }

    private static func transport(_ spec: TransportSpec) -> String {
        switch spec { case .udp: "{\"kind\":\"udp\"}" }
    }

    private static func create(_ configuration: EngineConfiguration, callbacks: CallbackBox) throws(EngineError) -> Int64 {
        // Zero-initialise the C aggregate; every pointer below is scoped through create.
        var params = unsafe wgex_create_params()
        switch configuration.tun {
        case let .networkExtension(descriptor): unsafe params.tun_kind = 0; unsafe params.tun_fd = descriptor
        case let .packetDescriptor(descriptor, mtu): unsafe params.tun_kind = 1; unsafe params.tun_fd = descriptor; unsafe params.mtu = mtu
        case let .createUTun(mtu): unsafe params.tun_kind = 2; unsafe params.mtu = mtu
        }
        unsafe params.bind_ifindex_v4 = try index(configuration.bindInterfaceIndexV4)
        unsafe params.bind_ifindex_v6 = try index(configuration.bindInterfaceIndexV6)
        unsafe params.log_level = configuration.logLevel.rawValue
        unsafe params.mobile_quirks = configuration.mobileQuirks ? 1 : 0
        unsafe params.log = CallbackBox.logTrampoline
        unsafe params.event = CallbackBox.eventTrampoline
        // The actor (and this argument until init completes) owns the box through destroy.
        unsafe params.log_ctx = Unmanaged.passUnretained(callbacks).toOpaque()
        unsafe params.event_ctx = params.log_ctx
        let json = transport(configuration.transport)
        // Keep process configuration and create in the same critical section. Identical
        // limits are applied once; Go rejects a first configure after any prior create.
        let result: Result<Int64, EngineError> = processLimits.withLock { applied in
            if let limits = configuration.processLimits {
                if let applied {
                    guard applied == limits else { return .failure(.state) }
                } else {
                    var process = wgex_process_params(
                        memory_limit_bytes: limits.memoryLimitBytes, gc_percent: limits.gcPercent, queue_profile: limits.queueProfile,
                    )
                    // C reads this stack struct synchronously and retains no pointer to it.
                    let code = unsafe wgex_configure_process(&process)
                    if let error = EngineError(code: code) {
                        return .failure(error)
                    }
                    applied = limits
                }
            }
            // Both scoped C strings and the stack struct live through create. Only
            // callback contexts are retained by Go; kind 2 requires the name "utun".
            let handle = json.withCString { string in
                unsafe params.transport_json = string
                return "utun".withCString { name in
                    if case .createUTun = configuration.tun {
                        unsafe params.tun_name = name
                    }
                    return unsafe wgex_create(&params)
                }
            }
            if handle <= 0 {
                return .failure(EngineError(code: Int32(clamping: handle)) ?? .internal)
            }
            return .success(handle)
        }
        return try result.get()
    }
}
