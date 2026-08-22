import Authentication
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var identityIdentifierFlow: TestFlow {
        TestFlow(
            "identity-identifiers",
            tags: [
                "authentication",
                "identity",
                "uuid",
            ]
        ) {
            Step("system identity accepts UUID") {
                let identifier = try SystemIdentityIdentifier(
                    "45b788e8-8078-4a94-9f56-e1ddba460d28"
                )

                try Expect.equal(
                    identifier.stringValue,
                    "45b788e8-8078-4a94-9f56-e1ddba460d28",
                    "identity.system.uuid"
                )
            }

            Step("system identity rejects non-UUID") {
                try Expect.throwsError(
                    "identity.system.invalid"
                ) {
                    _ = try SystemIdentityIdentifier(
                        "principal:test-user"
                    )
                }
            }

            Step("system identity Codable round-trips") {
                let original = try SystemIdentityIdentifier(
                    "45b788e8-8078-4a94-9f56-e1ddba460d28"
                )

                let encoded = try JSONEncoder().encode(
                    original
                )

                let decoded = try JSONDecoder().decode(
                    SystemIdentityIdentifier.self,
                    from: encoded
                )

                try Expect.equal(
                    decoded,
                    original,
                    "identity.system.codable"
                )
            }

            Step("session accepts UUID") {
                let identifier = try SessionIdentifier(
                    "6873abe1-e093-4323-9791-98de24e0f918"
                )

                try Expect.equal(
                    identifier.stringValue,
                    "6873abe1-e093-4323-9791-98de24e0f918",
                    "identity.session.uuid"
                )
            }

            Step("session rejects non-UUID") {
                try Expect.throwsError(
                    "identity.session.invalid"
                ) {
                    _ = try SessionIdentifier(
                        "session:test-session"
                    )
                }
            }

            Step("random identifiers are distinct") {
                let first = SystemIdentityIdentifier.random()
                let second = SystemIdentityIdentifier.random()

                try Expect.equal(
                    first == second,
                    false,
                    "identity.system.random.distinct"
                )
            }
        }
    }
}
