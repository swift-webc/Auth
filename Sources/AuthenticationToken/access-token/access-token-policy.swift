import Foundation

public struct AccessTokenPolicy:
    Sendable,
    Equatable
{
    public let issuer: AccessTokenIssuerIdentifier
    public let audience: AccessTokenAudienceIdentifier
    public let lifetimeSeconds: TimeInterval

    public init(
        issuer: AccessTokenIssuerIdentifier,
        audience: AccessTokenAudienceIdentifier,
        lifetimeSeconds: TimeInterval = 300
    ) throws {
        guard
            lifetimeSeconds.isFinite,
            lifetimeSeconds > 0
        else {
            throw AccessTokenError.invalidPolicy
        }

        self.issuer = issuer
        self.audience = audience
        self.lifetimeSeconds = lifetimeSeconds
    }
}
