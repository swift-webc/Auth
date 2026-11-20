import Authorization
import Authentication
import AuthenticationServer
import AuthenticationToken
import Foundation
import HTTP
import Server
import TestFlows

extension AuthenticationFlowSuite {
    static var serverAccessTokenProtectionFlow: TestFlow {
        TestFlow(
            "server-access-token-protection",
            tags: [
                "authentication",
                "server",
                "middleware",
                "jwt",
                "constraints",
                "scope",
            ]
        ) {
            Step("valid token reaches handler with typed authentication") {
                let fixture = try await serverAuthenticationFixture(
                    scopes: [
                        try AuthorizationScope(
                            "records:read"
                        ),
                    ]
                )

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client,
                    scopes: [
                        fixture.readScope,
                    ]
                )

                let response = await fixture.router.route(
                    authenticatedRequest(
                        token
                    )
                )

                try Expect.equal(
                    response.status.code,
                    200,
                    "server-authentication.valid.status"
                )

                try Expect.equal(
                    response.body,
                    fixture.systemIdentity.stringValue,
                    "server-authentication.valid.system-identity"
                )
            }

            Step("generic typed endpoint receives middleware authentication context") {
                let fixture = try await serverAuthenticationFixture(
                    scopes: [
                        try AuthorizationScope(
                            "records:read"
                        ),
                    ]
                )

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client,
                    scopes: [
                        fixture.readScope,
                    ]
                )

                let response = await fixture.router.route(
                    typedAuthenticatedRequest(
                        token
                    )
                )

                try Expect.equal(
                    response.status.code,
                    200,
                    "server-authentication.typed-endpoint.status"
                )

                try Expect.equal(
                    response.body.contains(
                        fixture.systemIdentity.stringValue
                    ),
                    true,
                    "server-authentication.typed-endpoint.system-identity"
                )

                try Expect.equal(
                    response.body.contains(
                        "typed-auth"
                    ),
                    true,
                    "server-authentication.typed-endpoint.input"
                )
            }

            Step("typed endpoint authentication executes before request conversion") {
                let fixture = try await serverAuthenticationFixture()

                let response = await fixture.router.route(
                    HTTPRequest(
                        method: .post,
                        path: "/private/typed",
                        body: "not-json"
                    )
                )

                try Expect.equal(
                    response.status.code,
                    401,
                    "server-authentication.typed-endpoint.authentication-first"
                )
            }

            Step("missing bearer token is unauthorized") {
                let fixture = try await serverAuthenticationFixture()

                let response = await fixture.router.route(
                    HTTPRequest(
                        method: .get,
                        path: "/private"
                    )
                )

                try Expect.equal(
                    response.status.code,
                    401,
                    "server-authentication.missing.status"
                )
            }

            Step("malformed bearer token is unauthorized") {
                let fixture = try await serverAuthenticationFixture()

                let response = await fixture.router.route(
                    HTTPRequest(
                        method: .get,
                        path: "/private",
                        headers: [
                            "Authorization": "Bearer aaa.bbb.ccc",
                        ]
                    )
                )

                try Expect.equal(
                    response.status.code,
                    401,
                    "server-authentication.invalid.status"
                )
            }

            Step("insufficient scope is forbidden") {
                let fixture = try await serverAuthenticationFixture(
                    scopes: [
                        try AuthorizationScope(
                            "records:write"
                        ),
                    ]
                )

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client,
                    scopes: [
                        fixture.readScope,
                    ]
                )

                let response = await fixture.router.route(
                    authenticatedRequest(
                        token
                    )
                )

                try Expect.equal(
                    response.status.code,
                    403,
                    "server-authentication.scope.status"
                )
            }

            Step("unexpected client is forbidden") {
                let allowedClient =
                    try ClientIdentifier(
                        "client:required-api"
                    )

                let fixture =
                    try await serverAuthenticationFixture(
                        constraints:
                            AccessTokenConstraints(
                                allowed: .init(
                                    clients: [
                                        allowedClient,
                                    ]
                                )
                            )
                    )

                let token =
                    try await fixture.issuer.issue(
                        systemIdentity:
                            fixture.systemIdentity,
                        session:
                            fixture.session,
                        client:
                            fixture.client
                    )

                let response =
                    await fixture.router.route(
                        authenticatedRequest(
                            token
                        )
                    )

                try Expect.equal(
                    response.status.code,
                    403,
                    "server-authentication.client.status"
                )
            }

            Step("missing required authentication method is forbidden") {
                let fixture =
                    try await serverAuthenticationFixture(
                        constraints:
                            AccessTokenConstraints(
                                required: .init(
                                    methods: [
                                        .password,
                                        .totp,
                                    ]
                                )
                            )
                    )

                let token =
                    try await fixture.issuer.issue(
                        systemIdentity:
                            fixture.systemIdentity,
                        session:
                            fixture.session,
                        client:
                            fixture.client,
                        authenticationMethods: [
                            .password,
                        ]
                    )

                let response =
                    await fixture.router.route(
                        authenticatedRequest(
                            token
                        )
                    )

                try Expect.equal(
                    response.status.code,
                    403,
                    "server-authentication.method.status"
                )
            }

            Step("missing required assurance is forbidden") {
                let fixture =
                    try await serverAuthenticationFixture(
                        constraints:
                            AccessTokenConstraints(
                                required: .init(
                                    assurances: [
                                        .multi_factor,
                                    ]
                                )
                            )
                    )

                let token =
                    try await fixture.issuer.issue(
                        systemIdentity:
                            fixture.systemIdentity,
                        session:
                            fixture.session,
                        client:
                            fixture.client,
                        authenticationMethods: [
                            .password,
                        ]
                    )

                let response =
                    await fixture.router.route(
                        authenticatedRequest(
                            token
                        )
                    )

                try Expect.equal(
                    response.status.code,
                    403,
                    "server-authentication.assurance.status"
                )
            }

            Step("stale authentication is forbidden") {
                let fixture =
                    try await serverAuthenticationFixture(
                        constraints:
                            try AccessTokenConstraints(
                                maximumAuthenticationAge:
                                    30
                            )
                    )

                let issuedAt = Date()

                let token =
                    try await fixture.issuer.issue(
                        systemIdentity:
                            fixture.systemIdentity,
                        session:
                            fixture.session,
                        client:
                            fixture.client,
                        authenticatedAt:
                            issuedAt.addingTimeInterval(
                                -60
                            ),
                        issuedAt:
                            issuedAt
                    )

                let response =
                    await fixture.router.route(
                        authenticatedRequest(
                            token
                        )
                    )

                try Expect.equal(
                    response.status.code,
                    403,
                    "server-authentication.age.status"
                )
            }

            Step("token satisfying all constraints reaches handler") {
                let client = try ClientIdentifier(
                    "client:test-api"
                )

                let scope = try AuthorizationScope(
                    "records:read"
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

                let fixture =
                    try await serverAuthenticationFixture(
                        constraints: constraints
                    )

                let issuedAt = Date()

                let token =
                    try await fixture.issuer.issue(
                        systemIdentity:
                            fixture.systemIdentity,
                        session:
                            fixture.session,
                        client:
                            fixture.client,
                        scopes: [
                            fixture.readScope,
                        ],
                        authenticationMethods: [
                            .password,
                        ],
                        assurances: [
                            .multi_factor,
                        ],
                        authenticatedAt:
                            issuedAt.addingTimeInterval(
                                -60
                            ),
                        issuedAt:
                            issuedAt
                    )

                let response =
                    await fixture.router.route(
                        authenticatedRequest(
                            token
                        )
                    )

                try Expect.equal(
                    response.status.code,
                    200,
                    "server-authentication.constraints.status"
                )

                try Expect.equal(
                    response.body,
                    fixture
                        .systemIdentity
                        .stringValue,
                    "server-authentication.constraints.system-identity"
                )
            }

            Step("authentication context is restored after routing") {
                let fixture = try await serverAuthenticationFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                _ = await fixture.router.route(
                    authenticatedRequest(
                        token
                    )
                )

                try Expect.equal(
                    AuthenticatedAccessToken.currentIfPresent(),
                    nil,
                    "server-authentication.context.restored"
                )

                try Expect.throwsError(
                    "server-authentication.context.required"
                ) {
                    _ = try AuthenticatedAccessToken.current()
                }

                let request = HTTPRequest(
                    method: .get,
                    path: "/outside"
                )

                try Expect.equal(
                    request.authenticationIfPresent(),
                    nil,
                    "server-authentication.context.request-facade"
                )

                try Expect.throwsError(
                    "server-authentication.context.request-facade-required"
                ) {
                    _ = try request.authentication()
                }
            }

            Step("concurrent authenticated requests remain isolated") {
                let fixture = try await serverAuthenticationFixture()

                let firstSystemIdentity = try SystemIdentityIdentifier(
                    "bd07d39d-4faa-4b02-a6c1-eabec1363afd"
                )

                let secondSystemIdentity = try SystemIdentityIdentifier(
                    "b9ea606a-ce22-4ef0-9521-2f4c35a1f95b"
                )

                let firstToken = try await fixture.issuer.issue(
                    systemIdentity: firstSystemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                let secondToken = try await fixture.issuer.issue(
                    systemIdentity: secondSystemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                async let firstResponse = fixture.router.route(
                    authenticatedRequest(
                        firstToken
                    )
                )

                async let secondResponse = fixture.router.route(
                    authenticatedRequest(
                        secondToken
                    )
                )

                let responses = await (
                    firstResponse,
                    secondResponse
                )

                try Expect.equal(
                    responses.0.body,
                    firstSystemIdentity.stringValue,
                    "server-authentication.concurrent.first"
                )

                try Expect.equal(
                    responses.1.body,
                    secondSystemIdentity.stringValue,
                    "server-authentication.concurrent.second"
                )
            }
        }
    }
}

private struct TypedProtectedRequest: Decodable, HTTPRequestable {
    let value: String
}

private struct TypedProtectedResponse: Encodable, HTTPRespondable {
    let systemIdentity: String
    let value: String
}

private let typedProtectedEndpoint = Endpoint<
    TypedProtectedRequest,
    TypedProtectedResponse
>(
    method: .post,
    "private",
    "typed"
)

private struct ServerAuthenticationFixture: Sendable {
    let issuer: AccessTokenIssuer
    let verifier: AccessTokenVerifier
    let router: Router

    let systemIdentity: SystemIdentityIdentifier
    let session: SessionIdentifier
    let client: ClientIdentifier

    let readScope: AuthorizationScope
}

private func serverAuthenticationFixture(
    constraints: AccessTokenConstraints
) async throws -> ServerAuthenticationFixture {
    let policy = try AccessTokenPolicy(
        issuer: AccessTokenIssuerIdentifier(
            "https://auth.depaix.systems"
        ),
        audience: AccessTokenAudienceIdentifier(
            "api.depaix.systems"
        ),
        lifetimeSeconds: 300
    )

    let signingKey = try AccessTokenSigningKey(
        identifier: AccessTokenKeyIdentifier(
            "authentication-server-test"
        ),
        privateKeyPEM: authenticationServerPrivateKeyPEM
    )

    let verificationKey = try AccessTokenVerificationKey(
        identifier: AccessTokenKeyIdentifier(
            "authentication-server-test"
        ),
        publicKeyPEM: authenticationServerPublicKeyPEM
    )

    let issuer = try await AccessTokenIssuer(
        signingKey: signingKey,
        policy: policy
    )

    let verifier = try await AccessTokenVerifier(
        verificationKeys: [
            verificationKey,
        ],
        policy: policy
    )

    let protected = AccessTokenProtection(
        verifier: verifier,
        constraints: constraints
    )

    let router = Router(
        routes: Server.routes {
            get("private") { request, _ in
                try? await Task.sleep(
                    for: .milliseconds(5)
                )

                do {
                    let authentication = try request.authentication()

                    return .ok(
                        body: authentication
                            .claims
                            .systemIdentity
                            .stringValue
                    )
                } catch {
                    return .internalServerError(
                        body: "Authentication context unavailable."
                    )
                }
            }
            .use(protected)

            route(
                typedProtectedEndpoint
            ) { request in
                let authentication = try AuthenticatedAccessToken.current()

                return TypedProtectedResponse(
                    systemIdentity: authentication
                        .claims
                        .systemIdentity
                        .stringValue,
                    value: request.value
                )
            }
            .use(protected)
        }
    )

    return ServerAuthenticationFixture(
        issuer: issuer,
        verifier: verifier,
        router: router,
        systemIdentity: try SystemIdentityIdentifier(
            "45b788e8-8078-4a94-9f56-e1ddba460d28"
        ),
        session: try SessionIdentifier(
            "6873abe1-e093-4323-9791-98de24e0f918"
        ),
        client: try ClientIdentifier(
            "client:test-api"
        ),
        readScope: try AuthorizationScope(
            "records:read"
        )
    )
}

private func serverAuthenticationFixture(
    scopes: Set<AuthorizationScope> = []
) async throws -> ServerAuthenticationFixture {
    try await serverAuthenticationFixture(
        constraints: AccessTokenConstraints(
            required: .init(
                scopes: scopes
            )
        )
    )
}

private func authenticatedRequest(
    _ token: AccessToken
) -> HTTPRequest {
    HTTPRequest(
        method: .get,
        path: "/private",
        headers: [
            "Authorization": "Bearer \(token.encoded)",
        ]
    )
}

private func typedAuthenticatedRequest(
    _ token: AccessToken
) -> HTTPRequest {
    HTTPRequest(
        method: .post,
        path: "/private/typed",
        headers: [
            "Authorization": "Bearer \(token.encoded)",
            "Content-Type": "application/json",
        ],
        body: """
        {
            "value": "typed-auth"
        }
        """
    )
}

private let authenticationServerPrivateKeyPEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMh5X0M3qRTra62fccbjPirzgTrrldER2+wDvoS1J0/UoAoGCCqGSM49
AwEHoUQDQgAE2XPUh8nAqh1dG7e52X4zuKB7BHoxlASqlkBeijgo4LEMZj2smXUi
e3KTjCUMMunYtbu+dLIcdgUVRzrX0wje9g==
-----END EC PRIVATE KEY-----
"""

private let authenticationServerPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2XPUh8nAqh1dG7e52X4zuKB7BHox
lASqlkBeijgo4LEMZj2smXUie3KTjCUMMunYtbu+dLIcdgUVRzrX0wje9g==
-----END PUBLIC KEY-----
"""
