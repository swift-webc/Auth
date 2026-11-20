import AuthorizationCapability
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var capabilityFlow:
        TestFlow
    {
        TestFlow(
            "authorization-capability",
            tags: [
                "authentication",
                "authorization",
                "capability",
                "cryptography",
            ]
        ) {
            Step(
                "generated secret is URL-safe and redacted"
            ) {
                let secret =
                    try CapabilitySecrets.generate()

                try Expect.equal(
                    secret.transportValue.contains(
                        "+"
                    ),
                    false,
                    "capability.url-safe.plus"
                )

                try Expect.equal(
                    secret.transportValue.contains(
                        "/"
                    ),
                    false,
                    "capability.url-safe.slash"
                )

                try Expect.equal(
                    secret.transportValue.contains(
                        "="
                    ),
                    false,
                    "capability.url-safe.padding"
                )

                try Expect.equal(
                    secret.description,
                    "<redacted capability secret>",
                    "capability.description.redacted"
                )
            }

            Step(
                "secret round-trips through transport representation"
            ) {
                let original =
                    try CapabilitySecrets.generate()

                let decoded =
                    try CapabilitySecret(
                        transportValue:
                            original.transportValue
                    )

                try Expect.equal(
                    decoded.transportValue,
                    original.transportValue,
                    "capability.transport.round-trip"
                )
            }

            Step(
                "digest is deterministic and verifies"
            ) {
                let secret =
                    try CapabilitySecrets.generate()

                let first =
                    try CapabilitySecrets.digest(
                        secret
                    )

                let second =
                    try CapabilitySecrets.digest(
                        secret
                    )

                try Expect.equal(
                    first,
                    second,
                    "capability.digest.deterministic"
                )

                try Expect.equal(
                    try CapabilitySecrets.verify(
                        secret,
                        against:
                            first
                    ),
                    true,
                    "capability.digest.verifies"
                )
            }

            Step(
                "different secret does not verify"
            ) {
                let first =
                    try CapabilitySecrets.generate()

                let second =
                    try CapabilitySecrets.generate()

                let digest =
                    try CapabilitySecrets.digest(
                        first
                    )

                try Expect.equal(
                    try CapabilitySecrets.verify(
                        second,
                        against:
                            digest
                    ),
                    false,
                    "capability.digest.rejects-other-secret"
                )
            }

            Step(
                "digest Codable is single-value and round-trips"
            ) {
                let secret =
                    try CapabilitySecrets.generate()

                let digest =
                    try CapabilitySecrets.digest(
                        secret
                    )

                let encoded =
                    try JSONEncoder().encode(
                        digest
                    )

                let decoded =
                    try JSONDecoder().decode(
                        CapabilityDigest.self,
                        from:
                            encoded
                    )

                try Expect.equal(
                    decoded,
                    digest,
                    "capability.digest.codable"
                )
            }

            Step(
                "malformed capability secret is rejected"
            ) {
                try Expect.throwsError(
                    "capability.secret.invalid"
                ) {
                    _ =
                        try CapabilitySecret(
                            transportValue:
                                "not-a-capability-secret"
                        )
                }
            }
        }
    }
}
