import Authorization
import Authentication
import TestFlows

extension AuthenticationFlowSuite {
    static var authorizationFlow:
        TestFlow
    {
        TestFlow(
            "authorization",
            tags: [
                "authentication",
                "authorization",
                "scope",
                "authority",
            ]
        ) {
            Step(
                "authorization scope validates"
            ) {
                let scope =
                    try AuthorizationScope(
                        "agreement:view"
                    )

                try Expect.equal(
                    scope.rawValue,
                    "agreement:view",
                    "authorization.scope.raw-value"
                )
            }

            Step(
                "scoped authority grants one and many"
            ) {
                let read =
                    try AuthorizationScope(
                        "agreement:view"
                    )

                let accept =
                    try AuthorizationScope(
                        "agreement:accept"
                    )

                let authority =
                    TestScopedAuthority(
                        scopes: [
                            read,
                            accept,
                        ]
                    )

                try Expect.equal(
                    authority.grants(
                        read
                    ),
                    true,
                    "authorization.grants.one"
                )

                try Expect.equal(
                    authority.grants(
                        all: [
                            read,
                            accept,
                        ]
                    ),
                    true,
                    "authorization.grants.all"
                )
            }

            Step(
                "missing scope is rejected"
            ) {
                let read =
                    try AuthorizationScope(
                        "agreement:view"
                    )

                let accept =
                    try AuthorizationScope(
                        "agreement:accept"
                    )

                let authority =
                    TestScopedAuthority(
                        scopes: [
                            read,
                        ]
                    )

                try Expect.throwsError(
                    "authorization.require.missing"
                ) {
                    try authority.require(
                        accept
                    )
                }
            }
        }
    }
}

private struct TestScopedAuthority:
    ScopedAuthority
{
    let scopes:
        Set<AuthorizationScope>
}
