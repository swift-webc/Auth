import Primitives

public enum AuthenticationAssurance:
    String,
    Sendable,
    Codable,
    Hashable,
    CaseIterable,
    StringParsableEnum
{
    case multi_factor
    case phishing_resistant
}
