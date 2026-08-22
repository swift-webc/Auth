import AuthenticationPassword
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var passwordFlow: TestFlow {
        TestFlow(
            "password",
            tags: [
                "authentication",
                "password",
                "cryptography",
            ]
        ) {
            Step("correct password is accepted") {
                let passwords = PasswordAuthentication()
                let hash = try passwords.hash(
                    "correct horse battery staple"
                )

                let verification = passwords.verify(
                    "correct horse battery staple",
                    against: hash
                )

                try Expect.equal(
                    verification,
                    .accepted(
                        rehash: false
                    ),
                    "password.correct.verification"
                )
            }

            Step("incorrect password is rejected") {
                let passwords = PasswordAuthentication()
                let hash = try passwords.hash(
                    "correct horse battery staple"
                )

                let verification = passwords.verify(
                    "incorrect password",
                    against: hash
                )

                try Expect.equal(
                    verification,
                    .rejected,
                    "password.incorrect.verification"
                )
            }

            Step("same password produces distinct salted hashes") {
                let passwords = PasswordAuthentication()
                let password = "same password"

                let first = try passwords.hash(
                    password
                )
                let second = try passwords.hash(
                    password
                )

                try Expect.notEqual(
                    first,
                    second,
                    "password.salt.distinct-hashes"
                )

                try Expect.hasPrefix(
                    first.encoded,
                    "$argon2id$",
                    "password.first.algorithm"
                )

                try Expect.hasPrefix(
                    second.encoded,
                    "$argon2id$",
                    "password.second.algorithm"
                )
            }

            Step("malformed hashes are rejected") {
                let malformedValues = [
                    "",
                    "not-a-password-hash",
                    "$argon2i$v=19$m=65536,t=2,p=1$salt$digest",
                    "$argon2id$v=18$m=65536,t=2,p=1$salt$digest",
                    "$argon2id$v=19$m=0,t=2,p=1$salt$digest",
                    "$argon2id$v=19$m=65536,t=2,p=1$salt with spaces$digest",
                ]

                for (
                    index,
                    malformed
                ) in malformedValues.enumerated() {
                    try Expect.throwsError(
                        "password.hash.malformed.\(index)"
                    ) {
                        _ = try PasswordHash(
                            malformed
                        )
                    }
                }
            }

            Step("Unicode password is preserved") {
                let passwords = PasswordAuthentication()
                let password = "påsswörd—密碼—🔐"

                let hash = try passwords.hash(
                    password
                )

                let verification = passwords.verify(
                    password,
                    against: hash
                )

                try Expect.equal(
                    verification,
                    .accepted(
                        rehash: false
                    ),
                    "password.unicode.verification"
                )
            }

            Step("changed policy requires rehashing") {
                let currentPolicy = PasswordPolicy.interactive
                let currentPasswords = PasswordAuthentication(
                    policy: currentPolicy
                )

                let hash = try currentPasswords.hash(
                    "policy migration test"
                )

                let changedPolicy = try PasswordPolicy(
                    operations: currentPolicy.operations + 1,
                    memoryBytes: currentPolicy.memoryBytes
                )

                let changedPasswords = PasswordAuthentication(
                    policy: changedPolicy
                )

                let verification = changedPasswords.verify(
                    "policy migration test",
                    against: hash
                )

                try Expect.equal(
                    verification,
                    .accepted(
                        rehash: true
                    ),
                    "password.policy.rehash"
                )
            }

            Step("invalid policy is rejected") {
                try Expect.throwsError(
                    "password.policy.zero-operations"
                ) {
                    _ = try PasswordPolicy(
                        operations: 0,
                        memoryBytes: 1
                    )
                }

                try Expect.throwsError(
                    "password.policy.zero-memory"
                ) {
                    _ = try PasswordPolicy(
                        operations: 1,
                        memoryBytes: 0
                    )
                }
            }

            Step("decoding cannot bypass hash validation") {
                let malformedJSON = Data(
                    "\"not-a-password-hash\"".utf8
                )

                try Expect.throwsError(
                    "password.hash.decoding-validation"
                ) {
                    _ = try JSONDecoder().decode(
                        PasswordHash.self,
                        from: malformedJSON
                    )
                }
            }
        }
    }
}
