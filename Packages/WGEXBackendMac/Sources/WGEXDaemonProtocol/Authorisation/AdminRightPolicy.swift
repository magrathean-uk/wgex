// SPDX-License-Identifier: MIT
import CoreFoundation
import Foundation

/// The only accepted policy for the daemon's administrative right.
///
/// A `rule`-class right with the single delegate `authenticate-admin-nonshared`, Apple's `user` rule for an
/// authenticated `admin` credential that is not shared and stays valid for 30 seconds. authd stores and returns a
/// rule-class right without `shared` or `timeout` (rule.c parses those keys only for the `user` class), so the
/// daemon's non-interactive recheck of the app's external form is decided by the delegate's timeout. The former
/// delegate `authenticate-admin` has a zero timeout: a credential that crossed to the daemon was always too old.
public struct AdminRightDefinition: Sendable, Equatable {
    /// Authorisation database class; only `rule` is accepted.
    public let ruleClass: String
    /// Delegated rules; exactly ``delegateName`` is accepted.
    public let rules: [String]
    /// Never present in a rule-class read-back.
    public let shared: Bool?
    /// Never present in a rule-class read-back.
    public let timeout: Int?

    private let weakeningKey: Bool

    /// Keys authd returns for a rule-class right (rule.c `rule_copy_to_cfobject`); any other key is refused.
    private static let allowedKeys: Set<String> = [
        "class", "rule", "k-of-n", "comment", "version", "created", "modified", "identifier", "requirement",
    ]

    /// Keys authd returns for the delegate's `user` class; any other key (mechanisms, entitlements) is refused.
    private static let delegateKeys: Set<String> = [
        "class", "group", "shared", "timeout", "tries", "authenticate-user", "allow-root", "session-owner",
        "comment", "version", "created", "modified", "identifier", "requirement",
    ]

    /// Apple's built-in delegate that carries the authentication.
    public static let delegateName = "authenticate-admin-nonshared"

    /// Longest delegate credential lifetime accepted, in seconds; authd measures it from authentication.
    public static let maximumDelegateTimeout = 30

    /// The exact dictionary the root daemon writes.
    public static var canonicalDictionary: [String: Any] {
        [
            "class": "rule",
            "rule": [delegateName],
            "comment": "WGEX administrator authorisation; authenticate-admin-nonshared, not shared, 30 seconds",
        ]
    }

    /// Creates a database observation; `shared` or `timeout` cannot belong to a rule-class read-back.
    public init(ruleClass: String, rules: [String], shared: Bool? = nil, timeout: Int? = nil) {
        self.ruleClass = ruleClass; self.rules = rules; self.shared = shared; self.timeout = timeout
        weakeningKey = shared != nil || timeout != nil
    }

    /// Interprets authd's normalised result without coercing types.
    public init(dictionary: [String: Any]) throws {
        guard let value = dictionary["class"] as? String else { throw DaemonError.notAuthorised(.adminRightRequired) }
        ruleClass = value
        rules = (dictionary["rule"] as? [String]) ?? (dictionary["rule"] as? String).map { [$0] } ?? []
        shared = Self.boolean(dictionary["shared"]); timeout = Self.integer(dictionary["timeout"])
        let validThreshold = dictionary["k-of-n"].map { Self.integer($0) == 1 } ?? true
        weakeningKey = !Set(dictionary.keys).isSubset(of: Self.allowedKeys) || !validThreshold
            || (dictionary["rule"] != nil && dictionary["rule"] as? [String] == nil && dictionary["rule"] as? String == nil)
    }

    fileprivate var authenticatesAdmin: Bool {
        !weakeningKey && ruleClass == "rule" && rules == [Self.delegateName]
    }

    /// Accepts the delegate's read-back only as an authenticated, unshared `admin` credential that expires within
    /// ``maximumDelegateTimeout`` seconds; a shared, longer-lived, root, owner-only or mechanism rule is weaker.
    public static func acceptsDelegate(_ dictionary: [String: Any]) -> Bool {
        guard Set(dictionary.keys).isSubset(of: delegateKeys),
              dictionary["class"] as? String == "user", dictionary["group"] as? String == "admin",
              let lifetime = integer(dictionary["timeout"]), (1 ... maximumDelegateTimeout).contains(lifetime)
        else { return false }
        func flag(_ key: String, default value: Bool) -> Bool? {
            dictionary[key] == nil ? value : boolean(dictionary[key])
        }
        return flag("shared", default: false) == false && flag("authenticate-user", default: true) == true
            && flag("allow-root", default: false) == false && flag("session-owner", default: false) == false
    }

    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.rounded() == number.doubleValue, abs(number.doubleValue) < 1e15 else { return nil }
        return number.intValue
    }

    /// Root writes this definition at every startup; it reads back with no `shared` or `timeout`.
    public static let required = AdminRightDefinition(ruleClass: "rule", rules: [delegateName])
}

/// Injectable authorisation database seam. Reads occur again for every administrative request.
public struct AdminRightPolicy: Sendable {
    private let read: @Sendable () throws -> AdminRightDefinition
    private let write: @Sendable () throws -> Void

    /// Production supplies AuthorizationRightGet/Set; tests never access the host database.
    public init(read: @escaping @Sendable () throws -> AdminRightDefinition, write: @escaping @Sendable () throws -> Void) {
        self.read = read; self.write = write
    }

    /// Replaces even a pre-created allow rule and verifies the database's resulting policy.
    public func install() throws {
        try write()
        guard isValid() else { throw DaemonError.notAuthorised(.adminRightRequired) }
    }

    /// Rejects missing or malformed forms before making any authorisation database call.
    public func validateExternalForm(_ bytes: Data?, byteCount: Int, verify: (Data) -> Bool) -> Bool {
        guard let bytes, bytes.count == byteCount else { return false }
        return isValid() && verify(bytes)
    }

    /// Missing, unreadable, compound or permissive rules fail closed.
    public func isValid() -> Bool {
        (try? read().authenticatesAdmin) == true
    }
}
