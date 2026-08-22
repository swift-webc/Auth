import Authorization
import Authentication
import AuthenticationToken
import Server

public struct AuthenticatedAccessToken:
    Sendable,
    Hashable,
    ScopedAuthority
{
    public let token:
        AccessToken

    public let claims:
        AccessTokenClaims

    public init(
        token:
            AccessToken,
        claims:
            AccessTokenClaims
    ) {
        self.token =
            token

        self.claims =
            claims
    }

    public var scopes:
        Set<AuthorizationScope>
    {
        claims.scopes
    }

    public static func current()
        throws
        -> Self
    {
        guard
            let authentication =
                currentIfPresent()
        else {
            throw AuthenticationServerError
                .missingAuthenticationContext
        }

        return authentication
    }

    public static func currentIfPresent()
        -> Self?
    {
        ServerRequestScope.value(
            for:
                AccessTokenAuthenticationContextKey.self
        )
    }
}
