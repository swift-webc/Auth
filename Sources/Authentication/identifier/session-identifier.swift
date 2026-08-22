import Foundation
import Primitives

public struct SessionIdentifier: UUIDIdentifier
{
    public let rawValue: UUID

    public init(
        rawValue: UUID
    ) {
        self.rawValue = rawValue
    }
}
