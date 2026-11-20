import Authorization
import Authentication
import AuthenticationToken
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var accessTokenConstraintsFlow:
        TestFlow
    {
        TestFlow(
            "access-token-constraints",
            tags: [
                "authentication",
                "token",
                "constraints",
                "evaluation",
            ]
        ) {
            Step(
                "constraint namespaces expose policy"
            ) {
                let scope =
                    try AuthorizationScope(
                        "records:read"
                    )

                let client =
                    try ClientIdentifier(
                        "client:test-api"
                    )

                let constraints =
                    try AccessTokenConstraints(
                        required: .init(
                            scopes: [
                                scope,
                            ],
                            methods: [
                                .password,
                            ],
                            assurances: [
                                .multi_factor,
                            ]
                        ),
                        allowed: .init(
                            clients: [
                                client,
                            ]
                        ),
                        maximumAuthenticationAge:
                            300
                    )

                try Expect.equal(
                    constraints.required.scopes,
                    [
                        scope,
                    ],
                    "access-token-constraints.required.scopes"
                )

                try Expect.equal(
                    constraints.required.methods,
                    [
                        .password,
                    ],
                    "access-token-constraints.required.methods"
                )

                try Expect.equal(
                    constraints.required.assurances,
                    [
                        .multi_factor,
                    ],
                    "access-token-constraints.required.assurances"
                )

                try Expect.equal(
                    constraints.allowed.clients,
                    [
                        client,
                    ],
                    "access-token-constraints.allowed.clients"
                )

                try Expect.equal(
                    constraints.maximum.authenticationAge,
                    300,
                    "access-token-constraints.maximum.authentication-age"
                )
            }

            Step(
                "evaluation collects all violations"
            ) {
                let now = Date(
                    timeIntervalSince1970:
                        1_800_000_000
                )

                let readScope =
                    try AuthorizationScope(
                        "records:read"
                    )

                let writeScope =
                    try AuthorizationScope(
                        "records:write"
                    )

                let allowedClient =
                    try ClientIdentifier(
                        "client:allowed"
                    )

                let actualClient =
                    try ClientIdentifier(
                        "client:actual"
                    )

                let constraints =
                    try AccessTokenConstraints(
                        required: .init(
                            scopes: [
                                readScope,
                                writeScope,
                            ],
                            methods: [
                                .password,
                                .totp,
                            ],
                            assurances: [
                                .multi_factor,
                            ]
                        ),
                        allowed: .init(
                            clients: [
                                allowedClient,
                            ]
                        ),
                        maximumAuthenticationAge:
                            30
                    )

                let claims =
                    try accessTokenConstraintClaims(
                        client: actualClient,
                        scopes: [
                            readScope,
                        ],
                        authenticationMethods: [
                            .password,
                        ],
                        authenticatedAt:
                            now.addingTimeInterval(
                                -60
                            ),
                        issuedAt:
                            now
                    )

                let evaluation =
                    constraints.evaluate(
                        claims,
                        at: now
                    )

                try Expect.equal(
                    evaluation.isSatisfied,
                    false,
                    "access-token-constraints.multiple.satisfied"
                )

                try Expect.equal(
                    evaluation.violations,
                    [
                        .missing_scopes(
                            [
                                writeScope,
                            ]
                        ),
                        .client_not_allowed(
                            actualClient
                        ),
                        .missing_authentication_methods(
                            [
                                .totp,
                            ]
                        ),
                        .missing_assurances(
                            [
                                .multi_factor,
                            ]
                        ),
                        .authentication_too_old(
                            maximumAge: 30,
                            actualAge: 60
                        ),
                    ],
                    "access-token-constraints.multiple.violations"
                )
            }

            Step(
                "nil and empty client allowlists differ"
            ) {
                let now = Date(
                    timeIntervalSince1970:
                        1_800_000_000
                )

                let client =
                    try ClientIdentifier(
                        "client:test-api"
                    )

                let claims =
                    try accessTokenConstraintClaims(
                        client: client,
                        authenticatedAt: now,
                        issuedAt: now
                    )

                let unrestricted =
                    AccessTokenConstraints()

                try Expect.equal(
                    unrestricted
                        .evaluate(
                            claims,
                            at: now
                        )
                        .isSatisfied,
                    true,
                    "access-token-constraints.clients.nil"
                )

                let noneAllowed =
                    AccessTokenConstraints(
                        allowed: .init(
                            clients: []
                        )
                    )

                try Expect.equal(
                    noneAllowed
                        .evaluate(
                            claims,
                            at: now
                        )
                        .violations,
                    [
                        .client_not_allowed(
                            client
                        ),
                    ],
                    "access-token-constraints.clients.empty"
                )
            }

            Step(
                "maximum authentication age is inclusive"
            ) {
                let now = Date(
                    timeIntervalSince1970:
                        1_800_000_000
                )

                let client =
                    try ClientIdentifier(
                        "client:test-api"
                    )

                let constraints =
                    try AccessTokenConstraints(
                        maximumAuthenticationAge:
                            60
                    )

                let claims =
                    try accessTokenConstraintClaims(
                        client: client,
                        authenticatedAt:
                            now.addingTimeInterval(
                                -60
                            ),
                        issuedAt:
                            now
                    )

                try Expect.equal(
                    constraints
                        .evaluate(
                            claims,
                            at: now
                        )
                        .isSatisfied,
                    true,
                    "access-token-constraints.age.boundary"
                )
            }

            Step(
                "future authentication time is reported"
            ) {
                let now = Date(
                    timeIntervalSince1970:
                        1_800_000_000
                )

                let client =
                    try ClientIdentifier(
                        "client:test-api"
                    )

                let issuedAt =
                    now.addingTimeInterval(
                        1
                    )

                let constraints =
                    try AccessTokenConstraints(
                        maximumAuthenticationAge:
                            60
                    )

                let claims =
                    try accessTokenConstraintClaims(
                        client: client,
                        authenticatedAt:
                            issuedAt,
                        issuedAt:
                            issuedAt
                    )

                try Expect.equal(
                    constraints
                        .evaluate(
                            claims,
                            at: now
                        )
                        .violations,
                    [
                        .authentication_time_in_future,
                    ],
                    "access-token-constraints.age.future"
                )
            }

            Step(
                "invalid maximum authentication age is rejected"
            ) {
                try Expect.throwsError(
                    "access-token-constraints.age.zero"
                ) {
                    _ = try AccessTokenConstraints(
                        maximumAuthenticationAge:
                            0
                    )
                }

                try Expect.throwsError(
                    "access-token-constraints.age.infinite"
                ) {
                    _ = try AccessTokenConstraints(
                        maximumAuthenticationAge:
                            .infinity
                    )
                }
            }
        }
    }
}

private func accessTokenConstraintClaims(
    client: ClientIdentifier,
    scopes: Set<AuthorizationScope> = [],
    authenticationMethods:
        Set<AuthenticationMethod> = [],
    assurances:
        Set<AuthenticationAssurance> = [],
    authenticatedAt: Date,
    issuedAt: Date
) throws -> AccessTokenClaims {
    try AccessTokenClaims(
        tokenIdentifier:
            AccessTokenIdentifier(
                "constraints-test-token"
            ),
        issuer:
            AccessTokenIssuerIdentifier(
                "https://auth.depaix.systems"
            ),
        audience:
            AccessTokenAudienceIdentifier(
                "api.depaix.systems"
            ),
        systemIdentity:
            SystemIdentityIdentifier(
                "45b788e8-8078-4a94-9f56-e1ddba460d28"
            ),
        session:
            SessionIdentifier(
                "6873abe1-e093-4323-9791-98de24e0f918"
            ),
        client:
            client,
        scopes:
            scopes,
        authenticationMethods:
            authenticationMethods,
        assurances:
            assurances,
        authenticatedAt:
            authenticatedAt,
        issuedAt:
            issuedAt,
        notBefore:
            issuedAt,
        expiresAt:
            issuedAt.addingTimeInterval(
                300
            )
    )
}
