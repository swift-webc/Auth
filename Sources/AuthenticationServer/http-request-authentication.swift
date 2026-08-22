import HTTP

public extension HTTPRequest {
    func authentication() throws -> AuthenticatedAccessToken {
        try AuthenticatedAccessToken.current()
    }

    func authenticationIfPresent() -> AuthenticatedAccessToken? {
        AuthenticatedAccessToken.currentIfPresent()
    }
}
