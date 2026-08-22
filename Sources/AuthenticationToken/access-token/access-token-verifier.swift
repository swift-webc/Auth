import JWTKit

public struct AccessTokenVerifier:
    Sendable
{
    public let policy: AccessTokenPolicy

    private let keys: JWTKeyCollection

    public init(
        verificationKeys: [AccessTokenVerificationKey],
        policy: AccessTokenPolicy
    ) async throws {
        guard !verificationKeys.isEmpty else {
            throw AccessTokenError.invalidKey
        }

        let keys = JWTKeyCollection()

        do {
            for verificationKey in verificationKeys {
                let publicKey = try ES256PublicKey(
                    pem: verificationKey.publicKeyPEM
                )

                await keys.add(
                    ecdsa: publicKey,
                    kid: JWKIdentifier(
                        string: verificationKey.identifier.rawValue
                    )
                )
            }
        } catch {
            throw AccessTokenError.invalidKey
        }

        self.policy = policy
        self.keys = keys
    }

    public func verify(
        _ token: AccessToken
    ) async throws -> AccessTokenClaims {
        let payload: JWTAccessTokenPayload

        do {
            payload = try await keys.verify(
                token.encoded,
                as: JWTAccessTokenPayload.self
            )
        } catch {
            throw AccessTokenError.verificationFailed
        }

        guard payload.iss.value == policy.issuer.rawValue else {
            throw AccessTokenError.unexpectedIssuer
        }

        guard payload.aud.value.contains(
            policy.audience.rawValue
        ) else {
            throw AccessTokenError.unexpectedAudience
        }

        guard payload.typ == "access" else {
            throw AccessTokenError.invalidTokenType
        }

        do {
            return try payload.accessTokenClaims()
        } catch let error as AccessTokenError {
            throw error
        } catch {
            throw AccessTokenError.invalidClaims
        }
    }
}
