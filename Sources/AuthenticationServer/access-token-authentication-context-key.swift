import Server

internal enum AccessTokenAuthenticationContextKey:
    ServerRequestContextKey
{
    typealias Value = AuthenticatedAccessToken
}
