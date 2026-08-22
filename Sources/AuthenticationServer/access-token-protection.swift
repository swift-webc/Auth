import AuthenticationToken
import HTTP
import Server

public struct AccessTokenProtection: Middleware {
    public let name =
        "access-token-protection"

    public let constraints:
        AccessTokenConstraints

    public let realm: String

    private let verifier:
        AccessTokenVerifier

    public init(
        verifier: AccessTokenVerifier,
        constraints: AccessTokenConstraints = .init(),
        realm: String = "api"
    ) {
        self.verifier = verifier
        self.constraints = constraints
        self.realm = realm
    }

    public func handle(
        _ request: HTTPRequest,
        _ router: Router,
        next: @Sendable (
            HTTPRequest,
            Router
        ) async -> HTTPResponse
    ) async -> HTTPResponse {
        guard let encoded =
            request.bearerToken()
        else {
            return .unauthorized(
                body:
                    "Missing or invalid Authorization header.",
                bearerRealm:
                    realm
            )
        }

        let token: AccessToken
        let claims: AccessTokenClaims

        do {
            token = try AccessToken(
                encoded
            )

            claims = try await verifier.verify(
                token
            )
        } catch {
            return .unauthorized(
                body:
                    "Invalid access token.",
                bearerError:
                    "invalid_token"
            )
        }

        let evaluation =
            constraints.evaluate(
                claims
            )

        guard evaluation.isSatisfied else {
            return .forbidden(
                body:
                    "Access token does not satisfy constraints."
            )
        }

        let authentication =
            AuthenticatedAccessToken(
                token: token,
                claims: claims
            )

        return await ServerRequestScope.withValue(
            authentication,
            for:
                AccessTokenAuthenticationContextKey.self
        ) {
            await next(
                request,
                router
            )
        }
    }
}
