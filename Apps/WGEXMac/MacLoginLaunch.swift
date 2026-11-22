// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Carbon
    import Darwin
    #if WGEX_LAB_BUILD
        import os
    #endif

    /// Recognises the system login-item launch event without inferring login from ordinary app activation.
    @MainActor
    public enum MacLoginLaunch {
        /// Handles the login-item property, the equivalent record flag and a login-session sender.
        public static func isLoginLaunch(_ event: NSAppleEventDescriptor?) -> Bool {
            signals(event)?.isLoginLaunch ?? false
        }

        /// Reduces the launch Apple event to the decision inputs; nil when no event is current.
        public static func signals(
            _ event: NSAppleEventDescriptor?,
            senderPID: (NSAppleEventDescriptor) -> pid_t = Self.senderPID,
            processName: (pid_t) -> String? = Self.processName,
        ) -> MacLaunchSignals? {
            guard let event else { return nil }
            let properties = event.paramDescriptor(forKeyword: keyAEPropData)
            let flag = event.paramDescriptor(forKeyword: keyAELaunchedAsLogInItem)?.booleanValue == true ||
                properties?.enumCodeValue == keyAELaunchedAsLogInItem ||
                properties?.forKeyword(keyAELaunchedAsLogInItem)?.booleanValue == true
            let pid = senderPID(event)
            return MacLaunchSignals(
                isOpenApplication: event.eventClass == kCoreEventClass && event.eventID == kAEOpenApplication,
                loginItemFlag: flag,
                sender: pid > 0 && pid != getpid() ? processName(pid) : nil,
            )
        }

        /// The process id the Apple Event Manager recorded for the event's sender, or 0 when it names none.
        public nonisolated static func senderPID(_ event: NSAppleEventDescriptor) -> pid_t {
            event.attributeDescriptor(forKeyword: keySenderPIDAttr)?.int32Value ?? 0
        }

        /// The executable name of a running process, read without privileges.
        public nonisolated static func processName(_ pid: pid_t) -> String? {
            var buffer = [UInt8](repeating: 0, count: 256)
            let length = proc_name(pid, &buffer, UInt32(buffer.count))
            guard length > 0 else { return nil }
            return String(decoding: buffer.prefix(Int(length)), as: UTF8.self)
        }

        /// A Lab build records what macOS sent at each launch stage so the LOGIN-SILENT rerun can show it.
        /// Only allowlisted metadata is logged: the event class and ID, the login-item flag, the sender and the
        /// decision. Event parameters (document paths, URLs, arbitrary payloads) are never read into the log.
        public static func logLaunchEvent(
            stage: String, event: NSAppleEventDescriptor?, isDefaultLaunch: Bool? = nil, isLoginLaunch: Bool,
        ) {
            #if WGEX_LAB_BUILD
                Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "launch").log(
                    "\(launchEventSummary(stage: stage, event: event, isDefaultLaunch: isDefaultLaunch, isLoginLaunch: isLoginLaunch), privacy: .public)",
                )
            #endif
        }

        /// The Lab launch log line: allowlisted metadata only, never the event descriptor or its parameters.
        public static func launchEventSummary(
            stage: String,
            event: NSAppleEventDescriptor?,
            isDefaultLaunch: Bool?,
            isLoginLaunch: Bool,
            senderPID: (NSAppleEventDescriptor) -> pid_t = Self.senderPID,
            processName: (pid_t) -> String? = Self.processName,
        ) -> String {
            let signals = signals(event, senderPID: senderPID, processName: processName)
            let eventClass = event.map { fourCharCode($0.eventClass) } ?? "none"
            let eventID = event.map { fourCharCode($0.eventID) } ?? "none"
            let pid = event.map { senderPID($0) } ?? 0
            let defaultLaunch = isDefaultLaunch.map { String($0) } ?? "n/a"
            return "Launch event \(stage): eventClass=\(eventClass) eventID=\(eventID) " +
                "openApplication=\(signals?.isOpenApplication ?? false) loginItemFlag=\(signals?.loginItemFlag ?? false) " +
                "senderPID=\(pid) sender=\(signals?.sender ?? "none") defaultLaunch=\(defaultLaunch) " +
                "loginLaunch=\(isLoginLaunch)"
        }

        /// A four-character code as text; any byte outside printable ASCII is shown as a question mark.
        public nonisolated static func fourCharCode(_ code: FourCharCode) -> String {
            let bytes = [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: code >> $0) }
            return String(bytes.map { (0x20 ... 0x7E).contains($0) ? Character(UnicodeScalar($0)) : "?" })
        }
    }
#endif
