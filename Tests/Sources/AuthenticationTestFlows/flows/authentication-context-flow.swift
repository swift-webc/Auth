import Authentication
import Primitives
import TestFlows

extension AuthenticationFlowSuite {
    static var authenticationContextFlow:
        TestFlow
    {
        TestFlow(
            "authentication-context",
            tags: [
                "authentication",
                "context",
                "parsing",
            ]
        ) {
            Step(
                "authentication method parses"
            ) {
                let value = try AuthenticationMethod(
                    parsing: "recovery_code"
                )

                try Expect.equal(
                    value,
                    .recovery_code,
                    "authentication.method.parse"
                )
            }

            Step(
                "authentication assurance parses"
            ) {
                let value = try AuthenticationAssurance(
                    parsing: "phishing_resistant"
                )

                try Expect.equal(
                    value,
                    .phishing_resistant,
                    "authentication.assurance.parse"
                )
            }

            Step(
                "unknown method is rejected"
            ) {
                try Expect.throwsError(
                    "authentication.method.invalid"
                ) {
                    _ = try AuthenticationMethod(
                        parsing: "invalid_method"
                    )
                }
            }

            Step(
                "method set parses"
            ) {
                let values = try parseEnumSet(
                    [
                        "password",
                        "totp",
                    ],
                    as: AuthenticationMethod.self
                )

                try Expect.equal(
                    values,
                    [
                        .password,
                        .totp,
                    ],
                    "authentication.method-set.parse"
                )
            }

            Step(
                "assurance set parses"
            ) {
                let values = try parseEnumSet(
                    [
                        "multi_factor",
                        "phishing_resistant",
                    ],
                    as: AuthenticationAssurance.self
                )

                try Expect.equal(
                    values,
                    [
                        .multi_factor,
                        .phishing_resistant,
                    ],
                    "authentication.assurance-set.parse"
                )
            }
        }
    }
}
