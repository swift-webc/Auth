import Foundation
import Sodium

public enum CapabilitySecretError:
    Error,
    LocalizedError,
    Sendable,
    Equatable
{
    case generation_failed
    case encoding_failed
    case invalid_secret
    case hashing_failed
    case invalid_digest

    public var errorDescription:
        String?
    {
        switch self {
        case .generation_failed:
            return """
            Secure capability-secret generation failed.
            """

        case .encoding_failed:
            return """
            Capability-secret encoding failed.
            """

        case .invalid_secret:
            return """
            The capability secret is malformed.
            """

        case .hashing_failed:
            return """
            Capability-secret hashing failed.
            """

        case .invalid_digest:
            return """
            The capability digest is malformed.
            """
        }
    }
}

public struct CapabilitySecret:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible
{
    public static let byteCount =
        32

    fileprivate let bytes:
        [UInt8]

    public let transportValue:
        String

    public init(
        transportValue:
            String
    ) throws {
        let sodium =
            Sodium()

        guard
            let bytes =
                sodium.utils.base642bin(
                    transportValue,
                    variant:
                        .URLSAFE_NO_PADDING
                ),
            bytes.count == Self.byteCount
        else {
            throw CapabilitySecretError
                .invalid_secret
        }

        self.bytes =
            bytes

        self.transportValue =
            transportValue
    }

    fileprivate init(
        bytes:
            [UInt8]
    ) throws {
        guard
            bytes.count == Self.byteCount
        else {
            throw CapabilitySecretError
                .invalid_secret
        }

        let sodium =
            Sodium()

        guard
            let encoded =
                sodium.utils.bin2base64(
                    bytes,
                    variant:
                        .URLSAFE_NO_PADDING
                )
        else {
            throw CapabilitySecretError
                .encoding_failed
        }

        self.bytes =
            bytes

        self.transportValue =
            encoded
    }

    public var description:
        String
    {
        "<redacted capability secret>"
    }

    public var debugDescription:
        String
    {
        description
    }
}

public struct CapabilityDigest:
    Sendable,
    Codable,
    Hashable
{
    public static let byteCount =
        32

    fileprivate let bytes:
        [UInt8]

    public let storageValue:
        String

    public init(
        storageValue:
            String
    ) throws {
        let sodium =
            Sodium()

        guard
            let bytes =
                sodium.utils.base642bin(
                    storageValue,
                    variant:
                        .URLSAFE_NO_PADDING
                ),
            bytes.count == Self.byteCount
        else {
            throw CapabilitySecretError
                .invalid_digest
        }

        self.bytes =
            bytes

        self.storageValue =
            storageValue
    }

    fileprivate init(
        bytes:
            [UInt8]
    ) throws {
        guard
            bytes.count == Self.byteCount
        else {
            throw CapabilitySecretError
                .invalid_digest
        }

        let sodium =
            Sodium()

        guard
            let encoded =
                sodium.utils.bin2base64(
                    bytes,
                    variant:
                        .URLSAFE_NO_PADDING
                )
        else {
            throw CapabilitySecretError
                .encoding_failed
        }

        self.bytes =
            bytes

        self.storageValue =
            encoded
    }

    public init(
        from decoder:
            Decoder
    ) throws {
        let container =
            try decoder
                .singleValueContainer()

        let value =
            try container.decode(
                String.self
            )

        do {
            try self.init(
                storageValue:
                    value
            )
        } catch {
            throw DecodingError
                .dataCorruptedError(
                    in:
                        container,
                    debugDescription:
                        "Invalid capability digest."
                )
        }
    }

    public func encode(
        to encoder:
            Encoder
    ) throws {
        var container =
            encoder
                .singleValueContainer()

        try container.encode(
            storageValue
        )
    }
}

public enum CapabilitySecrets {
    public static func generate()
        throws
        -> CapabilitySecret
    {
        let sodium =
            Sodium()

        guard
            let bytes =
                sodium.randomBytes.buf(
                    length:
                        CapabilitySecret.byteCount
                )
        else {
            throw CapabilitySecretError
                .generation_failed
        }

        return try CapabilitySecret(
            bytes:
                bytes
        )
    }

    public static func digest(
        _ secret:
            CapabilitySecret
    ) throws -> CapabilityDigest {
        let sodium =
            Sodium()

        guard
            let bytes =
                sodium.genericHash.hash(
                    message:
                        secret.bytes,
                    outputLength:
                        CapabilityDigest.byteCount
                )
        else {
            throw CapabilitySecretError
                .hashing_failed
        }

        return try CapabilityDigest(
            bytes:
                bytes
        )
    }

    public static func verify(
        _ secret:
            CapabilitySecret,
        against digest:
            CapabilityDigest
    ) throws -> Bool {
        let sodium =
            Sodium()

        guard
            let actual =
                sodium.genericHash.hash(
                    message:
                        secret.bytes,
                    outputLength:
                        CapabilityDigest.byteCount
                )
        else {
            throw CapabilitySecretError
                .hashing_failed
        }

        return sodium.utils.equals(
            actual,
            digest.bytes
        )
    }
}
