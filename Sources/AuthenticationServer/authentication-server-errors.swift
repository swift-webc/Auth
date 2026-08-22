import Foundation

public enum AuthenticationServerError:
    Error,
    LocalizedError,
    Sendable,
    Equatable
{
    case missingAuthenticationContext

    public var errorDescription: String? {
        switch self {
        case .missingAuthenticationContext:
            return "No authenticated access token is available for this request."
        }
    }
}
