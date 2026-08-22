import Primitives

public enum AuthenticationMethod:
    String,
    Sendable,
    Codable,
    Hashable,
    CaseIterable,
    StringParsableEnum
{
    case password
    case totp
    case passkey
    case recovery_code
}
