import Foundation

public enum PasswordError:
    Error,
    LocalizedError,
    Sendable,
    Equatable
{
    case invalidEncodedHash
    case invalidPolicy
    case hashingFailed

    public var errorDescription: String? {
        switch self {
        case .invalidEncodedHash:
            return "The encoded password hash is malformed or unsupported."

        case .invalidPolicy:
            return "The password-hashing policy contains invalid limits."

        case .hashingFailed:
            return "The password could not be securely hashed."
        }
    }
}
