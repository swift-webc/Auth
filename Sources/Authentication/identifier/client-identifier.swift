import Primitives

public struct ClientIdentifier: ValidatedStringIdentifier {
    public let rawValue: String

    public init(
        _ rawValue: String
    ) throws {
        self.rawValue = try parseStringIdentifierValue(
            rawValue,
            field: "client"
        )
    }
}
