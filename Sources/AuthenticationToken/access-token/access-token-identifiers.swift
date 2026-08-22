import Foundation
import Primitives

public struct AccessTokenIdentifier:
    ValidatedStringIdentifier
{
    public let rawValue: String

    public init(
        _ rawValue: String
    ) throws {
        self.rawValue = try parseStringIdentifierValue(
            rawValue,
            field: "token_identifier"
        )
    }

    public static func random() -> Self {
        Self(
            unchecked: UUID()
                .uuidString
                .lowercased()
        )
    }

    private init(
        unchecked rawValue: String
    ) {
        self.rawValue = rawValue
    }
}

public struct AccessTokenKeyIdentifier:
    ValidatedStringIdentifier
{
    public let rawValue: String

    public init(
        _ rawValue: String
    ) throws {
        self.rawValue = try parseStringIdentifierValue(
            rawValue,
            field: "key_identifier"
        )
    }
}

public struct AccessTokenIssuerIdentifier:
    ValidatedStringIdentifier
{
    public let rawValue: String

    public init(
        _ rawValue: String
    ) throws {
        self.rawValue = try parseStringIdentifierValue(
            rawValue,
            field: "issuer"
        )
    }
}

public struct AccessTokenAudienceIdentifier:
    ValidatedStringIdentifier
{
    public let rawValue: String

    public init(
        _ rawValue: String
    ) throws {
        self.rawValue = try parseStringIdentifierValue(
            rawValue,
            field: "audience"
        )
    }
}
