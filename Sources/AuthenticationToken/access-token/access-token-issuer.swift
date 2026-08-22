import Authorization
import Authentication
import Foundation
import JWTKit

public struct AccessTokenIssuer:
    Sendable
{
    public let policy: AccessTokenPolicy
    public let keyIdentifier: AccessTokenKeyIdentifier

    private let keys: JWTKeyCollection

    public init(
        signingKey: AccessTokenSigningKey,
        policy: AccessTokenPolicy
    ) async throws {
        let keys = JWTKeyCollection()

        do {
            let privateKey = try ES256PrivateKey(
                pem: signingKey.privateKeyPEM
            )

            await keys.add(
                ecdsa: privateKey,
                kid: JWKIdentifier(
                    string: signingKey.identifier.rawValue
                )
            )
        } catch {
            throw AccessTokenError.invalidKey
        }

        self.policy = policy
        self.keyIdentifier = signingKey.identifier
        self.keys = keys
    }

    public func issue(
        systemIdentity: SystemIdentityIdentifier,
        session: SessionIdentifier,
        client: ClientIdentifier,
        scopes: Set<AuthorizationScope> = [],
        authenticationMethods: Set<AuthenticationMethod> = [],
        assurances: Set<AuthenticationAssurance> = [],
        authenticatedAt: Date? = nil,
        issuedAt: Date = Date(),
        tokenIdentifier: AccessTokenIdentifier = .random()
    ) async throws -> AccessToken {
        let claims = try AccessTokenClaims(
            tokenIdentifier: tokenIdentifier,
            issuer: policy.issuer,
            audience: policy.audience,
            systemIdentity: systemIdentity,
            session: session,
            client: client,
            scopes: scopes,
            authenticationMethods: authenticationMethods,
            assurances: assurances,
            authenticatedAt: authenticatedAt ?? issuedAt,
            issuedAt: issuedAt,
            notBefore: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(
                policy.lifetimeSeconds
            )
        )

        let payload = JWTAccessTokenPayload(
            claims: claims
        )

        var header = JWTHeader()
        header.typ = "JWT"

        do {
            let encoded = try await keys.sign(
                payload,
                kid: JWKIdentifier(
                    string: keyIdentifier.rawValue
                ),
                header: header
            )

            return try AccessToken(
                encoded
            )
        } catch let error as AccessTokenError {
            throw error
        } catch {
            throw AccessTokenError.signingFailed
        }
    }
}
