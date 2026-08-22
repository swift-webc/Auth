public enum PasswordVerification:
    Sendable,
    Equatable
{
    case accepted(rehash: Bool)
    case rejected
}
