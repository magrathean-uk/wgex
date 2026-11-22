// SPDX-License-Identifier: MIT
import Foundation
import os
import WGEXCore

/// An allowlist of public dynamic values. No arbitrary string constructor is provided.
/// Keys, endpoint hosts and profile names cannot be wrapped as public values.
public enum PublicLogValue: Sendable {
    public enum Phase: String, Sendable { case idle, preparing, configuring, active, reasserting, stopping, failed }
    case phase(Phase)
    case errorCode(ConfigDiagnostic.Code)
    case interfaceIndex(UInt32)
    case generation(UInt64)
    case count(Int)
    case duration(Duration)

    fileprivate var text: String {
        switch self {
        case let .phase(value): value.rawValue
        case let .errorCode(value): value.rawValue
        case let .interfaceIndex(value): "utun\(value)"
        case let .generation(value): String(value)
        case let .count(value): String(value)
        case let .duration(value): String(describing: value)
        }
    }
}

/// Interpolations are private unless explicitly wrapped in ``PublicLogValue``.
/// Literal text must be static prose, never raw configuration or key material.
public struct LogMessage: ExpressibleByStringLiteral, ExpressibleByStringInterpolation, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible
{
    public struct StringInterpolation: StringInterpolationProtocol, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        public var description: String {
            "<LogInterpolation>"
        }

        public var debugDescription: String {
            description
        }

        fileprivate var rendered = ""
        fileprivate var publicText = ""
        fileprivate var privateText = ""

        public init(literalCapacity: Int, interpolationCount: Int) {}
        public mutating func appendLiteral(_ literal: String) {
            rendered += literal; publicText += literal
        }

        public mutating func appendInterpolation(_ value: some CustomStringConvertible) {
            let text = value.description
            rendered += text; publicText += "<private>"; privateText += text + "\n"
        }

        public mutating func appendInterpolation(_ value: PublicLogValue) {
            rendered += value.text; publicText += value.text
        }
    }

    private let interpolation: StringInterpolation
    public var description: String {
        "<LogMessage>"
    }

    public var debugDescription: String {
        description
    }

    public init(stringLiteral value: String) {
        var builder = StringInterpolation(literalCapacity: value.count, interpolationCount: 0)
        builder.appendLiteral(value); interpolation = builder
    }

    public init(stringInterpolation: StringInterpolation) {
        interpolation = stringInterpolation
    }

    package var publicText: String {
        interpolation.publicText
    }

    package var privateText: String {
        interpolation.privateText
    }

    fileprivate var rendered: String {
        interpolation.rendered
    }
}

/// Synchronous, nonisolated logging facade. The OS receives two fields: the public
/// template and a private interpolation payload. The ring retains the original for redaction.
public struct WGEXLogger: Sendable {
    private let logger: Logger
    private let category: LogCategory
    private let ring: LogRing

    public init(category: LogCategory, ring: LogRing = .process) {
        self.category = category; self.ring = ring
        logger = Logger(subsystem: LogCategory.subsystem, category: category.rawValue)
    }

    public func log(_ message: LogMessage, level: OSLogType = .default) {
        logger.log(level: level, "\(message.publicText, privacy: .public) \(message.privateText, privacy: .private)")
        ring.append(message.rendered, category: category)
    }
}
