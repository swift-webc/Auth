import Authorization
import Authentication
import AuthenticationToken
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var stringIdentifierFlow:
        TestFlow
    {
        TestFlow(
            "string-identifiers",
            tags: [
                "authentication",
                "identifier",
                "validation",
                "codable",
            ]
        ) {
            Step(
                "surrounding whitespace is normalized"
            ) {
                let identifier = try ClientIdentifier(
                    "  client:test-api  "
                )

                try Expect.equal(
                    identifier.rawValue,
                    "client:test-api",
                    "string-identifier.trimmed"
                )
            }

            Step(
                "empty identifier is rejected"
            ) {
                try Expect.throwsError(
                    "string-identifier.empty"
                ) {
                    _ = try ClientIdentifier(
                        "   "
                    )
                }
            }

            Step(
                "internal whitespace is rejected"
            ) {
                try Expect.throwsError(
                    "string-identifier.whitespace"
                ) {
                    _ = try AuthorizationScope(
                        "records: read"
                    )
                }
            }

            Step(
                "identifier Codable round-trips"
            ) {
                let original = try AuthorizationScope(
                    "records:read"
                )

                let encoded = try JSONEncoder().encode(
                    original
                )

                let decoded = try JSONDecoder().decode(
                    AuthorizationScope.self,
                    from: encoded
                )

                try Expect.equal(
                    decoded,
                    original,
                    "string-identifier.codable"
                )
            }

            Step(
                "decoding cannot bypass validation"
            ) {
                let malformed = Data(
                    "\"records: read\"".utf8
                )

                try Expect.throwsError(
                    "string-identifier.decode-validation"
                ) {
                    _ = try JSONDecoder().decode(
                        AuthorizationScope.self,
                        from: malformed
                    )
                }
            }

            Step(
                "access-token identifiers share validation"
            ) {
                let issuer =
                    try AccessTokenIssuerIdentifier(
                        "  https://auth.depaix.systems  "
                    )

                try Expect.equal(
                    issuer.rawValue,
                    "https://auth.depaix.systems",
                    "string-identifier.token.trimmed"
                )

                try Expect.throwsError(
                    "string-identifier.token.whitespace"
                ) {
                    _ = try AccessTokenAudienceIdentifier(
                        "api depaix"
                    )
                }
            }

            Step(
                "access-token identifier Codable is single-value"
            ) {
                let original =
                    try AccessTokenKeyIdentifier(
                        "auth-primary"
                    )

                let encoded = try JSONEncoder().encode(
                    original
                )

                let decoded = try JSONDecoder().decode(
                    AccessTokenKeyIdentifier.self,
                    from: encoded
                )

                try Expect.equal(
                    decoded,
                    original,
                    "string-identifier.token.codable"
                )
            }
        }
    }
}
