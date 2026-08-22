import Authorization
import Authentication
import JWTKit
import Primitives

internal struct JWTAccessTokenPayload:
    JWTPayload
{
    internal let iss: IssuerClaim
    internal let aud: AudienceClaim
    internal let sub: SubjectClaim
    internal let jti: IDClaim

    internal let iat: IssuedAtClaim
    internal let nbf: NotBeforeClaim
    internal let exp: ExpirationClaim

    internal let auth_time: IssuedAtClaim

    internal let sid: String
    internal let client: String
    internal let scope: String

    internal let amr: [String]
    internal let assurance: [String]

    internal let typ: String

    internal init(
        claims: AccessTokenClaims
    ) {
        self.iss = IssuerClaim(
            value: claims.issuer.rawValue
        )

        self.aud = AudienceClaim(
            value: [
                claims.audience.rawValue,
            ]
        )

        self.sub = SubjectClaim(
            value: claims.systemIdentity.stringValue
        )

        self.jti = IDClaim(
            value: claims.tokenIdentifier.rawValue
        )

        self.iat = IssuedAtClaim(
            value: claims.issuedAt
        )

        self.nbf = NotBeforeClaim(
            value: claims.notBefore
        )

        self.exp = ExpirationClaim(
            value: claims.expiresAt
        )

        self.auth_time = IssuedAtClaim(
            value: claims.authenticatedAt
        )

        self.sid = claims.session.stringValue
        self.client = claims.client.rawValue

        self.scope = claims.scopes
            .map(\.rawValue)
            .sorted()
            .joined(
                separator: " "
            )

        self.amr = claims.authenticationMethods
            .map(\.rawValue)
            .sorted()

        self.assurance = claims.assurances
            .map(\.rawValue)
            .sorted()

        self.typ = "access"
    }

    internal func verify(
        using algorithm: some JWTAlgorithm
    ) async throws {
        try exp.verifyNotExpired()
        try nbf.verifyNotBefore()

        guard typ == "access" else {
            throw AccessTokenError.invalidTokenType
        }
    }

    internal func accessTokenClaims() throws -> AccessTokenClaims {
        guard let rawAudience = aud.value.first else {
            throw AccessTokenError.invalidClaims
        }

        let scopes = try Set(
            scope
                .split(
                    separator: " ",
                    omittingEmptySubsequences: true
                )
                .map { rawScope in
                    try AuthorizationScope(
                        String(rawScope)
                    )
                }
        )

        let authenticationMethods = try parseEnumSet(
            amr,
            as: AuthenticationMethod.self
        )

        let assurances = try parseEnumSet(
            assurance,
            as: AuthenticationAssurance.self
        )

        return try AccessTokenClaims(
            tokenIdentifier: AccessTokenIdentifier(
                jti.value
            ),
            issuer: AccessTokenIssuerIdentifier(
                iss.value
            ),
            audience: AccessTokenAudienceIdentifier(
                rawAudience
            ),
            systemIdentity: SystemIdentityIdentifier(
                sub.value
            ),
            session: SessionIdentifier(
                sid
            ),
            client: ClientIdentifier(
                client
            ),
            scopes: scopes,
            authenticationMethods: authenticationMethods,
            assurances: assurances,
            authenticatedAt: auth_time.value,
            issuedAt: iat.value,
            notBefore: nbf.value,
            expiresAt: exp.value
        )
    }
}
