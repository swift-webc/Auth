import Foundation
import Primitives

public struct SystemIdentityIdentifier: UUIDIdentifier
{
    public let rawValue: UUID

    public init(
        rawValue: UUID
    ) {
        self.rawValue = rawValue
    }
}
