import Authorization
import Authentication
import Foundation

public struct AccessTokenClaims:
    Sendable,
    Codable,
    Hashable
{
    public let tokenIdentifier: AccessTokenIdentifier
    public let issuer: AccessTokenIssuerIdentifier
    public let audience: AccessTokenAudienceIdentifier

    public let systemIdentity: SystemIdentityIdentifier
    public let session: SessionIdentifier
    public let client: ClientIdentifier

    public let scopes: Set<AuthorizationScope>

    public let authenticationMethods: Set<AuthenticationMethod>
    public let assurances: Set<AuthenticationAssurance>
    public let authenticatedAt: Date

    public let issuedAt: Date
    public let notBefore: Date
    public let expiresAt: Date

    public init(
        tokenIdentifier: AccessTokenIdentifier,
        issuer: AccessTokenIssuerIdentifier,
        audience: AccessTokenAudienceIdentifier,
        systemIdentity: SystemIdentityIdentifier,
        session: SessionIdentifier,
        client: ClientIdentifier,
        scopes: Set<AuthorizationScope>,
        authenticationMethods: Set<AuthenticationMethod>,
        assurances: Set<AuthenticationAssurance>,
        authenticatedAt: Date,
        issuedAt: Date,
        notBefore: Date,
        expiresAt: Date
    ) throws {
        guard
            authenticatedAt <= issuedAt,
            expiresAt > issuedAt,
            expiresAt >= notBefore
        else {
            throw AccessTokenError.invalidTemporalClaims
        }

        self.tokenIdentifier = tokenIdentifier
        self.issuer = issuer
        self.audience = audience

        self.systemIdentity = systemIdentity
        self.session = session
        self.client = client

        self.scopes = scopes

        self.authenticationMethods = authenticationMethods
        self.assurances = assurances
        self.authenticatedAt = authenticatedAt

        self.issuedAt = issuedAt
        self.notBefore = notBefore
        self.expiresAt = expiresAt
    }
}
