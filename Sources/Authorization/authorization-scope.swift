import Primitives

public struct AuthorizationScope:
    ValidatedStringIdentifier
{
    public let rawValue: String

    public init(
        _ rawValue: String
    ) throws {
        self.rawValue =
            try parseStringIdentifierValue(
                rawValue,
                field:
                    "scope"
            )
    }
}
