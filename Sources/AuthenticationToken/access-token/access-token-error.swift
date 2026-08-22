import Foundation

public enum AccessTokenError:
    Error,
    LocalizedError,
    Sendable,
    Equatable
{
    case invalidPolicy
    case invalidConstraints
    case invalidTemporalClaims
    case invalidToken
    case invalidKey
    case signingFailed
    case verificationFailed
    case unexpectedIssuer
    case unexpectedAudience
    case invalidTokenType
    case invalidClaims

    public var errorDescription: String? {
        switch self {
        case .invalidPolicy:
            return "The access-token policy is invalid."

        case .invalidConstraints:
            return "The access-token constraints are invalid."

        case .invalidTemporalClaims:
            return "The access token contains invalid temporal claims."

        case .invalidToken:
            return "The encoded access token is malformed."

        case .invalidKey:
            return "The access-token signing or verification key is invalid."

        case .signingFailed:
            return "Access-token signing failed."

        case .verificationFailed:
            return "Access-token verification failed."

        case .unexpectedIssuer:
            return "The access token was issued by an unexpected authority."

        case .unexpectedAudience:
            return "The access token is not intended for this audience."

        case .invalidTokenType:
            return "The token is not an access token."

        case .invalidClaims:
            return "The access token contains invalid claims."
        }
    }
}
