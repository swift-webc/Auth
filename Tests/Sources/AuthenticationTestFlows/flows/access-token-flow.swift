import Authorization
import Authentication
import AuthenticationToken
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var accessTokenFlow: TestFlow {
        TestFlow(
            "access-token",
            tags: [
                "authentication",
                "token",
                "jwt",
                "es256",
            ]
        ) {
            Step("valid token round-trips claims") {
                let fixture = try await accessTokenFixture()
                let issuedAt = roundedNow()

                let authenticatedAt =
                    issuedAt.addingTimeInterval(
                        -120
                    )

                let identifier = try AccessTokenIdentifier(
                    "token-round-trip"
                )

                let authenticationMethods:
                    Set<AuthenticationMethod> = [
                        .password,
                        .totp,
                    ]

                let assurances:
                    Set<AuthenticationAssurance> = [
                        .multi_factor,
                    ]

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client,
                    scopes: fixture.scopes,
                    authenticationMethods: authenticationMethods,
                    assurances: assurances,
                    authenticatedAt: authenticatedAt,
                    issuedAt: issuedAt,
                    tokenIdentifier: identifier
                )

                let claims = try await fixture.verifier.verify(
                    token
                )

                try Expect.equal(
                    claims.tokenIdentifier,
                    identifier,
                    "access-token.identifier"
                )

                try Expect.equal(
                    claims.systemIdentity,
                    fixture.systemIdentity,
                    "access-token.system-identity"
                )

                try Expect.equal(
                    claims.session,
                    fixture.session,
                    "access-token.session"
                )

                try Expect.equal(
                    claims.client,
                    fixture.client,
                    "access-token.client"
                )

                try Expect.equal(
                    claims.scopes,
                    fixture.scopes,
                    "access-token.scopes"
                )

                try Expect.equal(
                    claims.authenticationMethods,
                    authenticationMethods,
                    "access-token.authentication-methods"
                )

                try Expect.equal(
                    claims.assurances,
                    assurances,
                    "access-token.assurances"
                )

                try Expect.equal(
                    claims.authenticatedAt,
                    authenticatedAt,
                    "access-token.authenticated-at"
                )

                try Expect.equal(
                    claims.issuedAt,
                    issuedAt,
                    "access-token.issued-at"
                )

                try Expect.equal(
                    claims.expiresAt,
                    issuedAt.addingTimeInterval(
                        fixture.policy.lifetimeSeconds
                    ),
                    "access-token.expires-at"
                )
            }

            Step("authentication time after issue is rejected") {
                let fixture = try await accessTokenFixture()
                let issuedAt = roundedNow()

                try await Expect.throwsError(
                    "access-token.authentication-time.future"
                ) {
                    _ = try await fixture.issuer.issue(
                        systemIdentity: fixture.systemIdentity,
                        session: fixture.session,
                        client: fixture.client,
                        authenticatedAt: issuedAt.addingTimeInterval(
                            1
                        ),
                        issuedAt: issuedAt
                    )
                }
            }

            Step("encoded token has three components") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                let componentCount = token.encoded.split(
                    separator: ".",
                    omittingEmptySubsequences: false
                ).count

                try Expect.equal(
                    componentCount,
                    3,
                    "access-token.components"
                )
            }

            Step("wrong public key is rejected") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                let wrongVerifier = try await AccessTokenVerifier(
                    verificationKeys: [
                        try rotatedVerificationKey(),
                    ],
                    policy: fixture.policy
                )

                try await Expect.throwsError(
                    "access-token.wrong-key"
                ) {
                    _ = try await wrongVerifier.verify(
                        token
                    )
                }
            }

            Step("wrong issuer is rejected") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                let wrongPolicy = try AccessTokenPolicy(
                    issuer: AccessTokenIssuerIdentifier(
                        "https://wrong.depaix.systems"
                    ),
                    audience: fixture.policy.audience,
                    lifetimeSeconds: fixture.policy.lifetimeSeconds
                )

                let wrongVerifier = try await AccessTokenVerifier(
                    verificationKeys: [
                        try primaryVerificationKey(),
                    ],
                    policy: wrongPolicy
                )

                try await Expect.throwsError(
                    "access-token.wrong-issuer"
                ) {
                    _ = try await wrongVerifier.verify(
                        token
                    )
                }
            }

            Step("wrong audience is rejected") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                let wrongPolicy = try AccessTokenPolicy(
                    issuer: fixture.policy.issuer,
                    audience: AccessTokenAudienceIdentifier(
                        "api.other.depaix.systems"
                    ),
                    lifetimeSeconds: fixture.policy.lifetimeSeconds
                )

                let wrongVerifier = try await AccessTokenVerifier(
                    verificationKeys: [
                        try primaryVerificationKey(),
                    ],
                    policy: wrongPolicy
                )

                try await Expect.throwsError(
                    "access-token.wrong-audience"
                ) {
                    _ = try await wrongVerifier.verify(
                        token
                    )
                }
            }

            Step("expired token is rejected") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client,
                    issuedAt: Date().addingTimeInterval(
                        -fixture.policy.lifetimeSeconds - 60
                    )
                )

                try await Expect.throwsError(
                    "access-token.expired"
                ) {
                    _ = try await fixture.verifier.verify(
                        token
                    )
                }
            }

            Step("future not-before token is rejected") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client,
                    issuedAt: Date().addingTimeInterval(
                        60
                    )
                )

                try await Expect.throwsError(
                    "access-token.not-before"
                ) {
                    _ = try await fixture.verifier.verify(
                        token
                    )
                }
            }

            Step("tampered payload is rejected") {
                let fixture = try await accessTokenFixture()

                let token = try await fixture.issuer.issue(
                    systemIdentity: fixture.systemIdentity,
                    session: fixture.session,
                    client: fixture.client
                )

                let tampered = try tamperPayload(
                    token
                )

                try await Expect.throwsError(
                    "access-token.tampered"
                ) {
                    _ = try await fixture.verifier.verify(
                        tampered
                    )
                }
            }

            Step("verification supports key rotation") {
                let primary = try await accessTokenFixture()

                let rotatedIssuer = try await AccessTokenIssuer(
                    signingKey: rotatedSigningKey(),
                    policy: primary.policy
                )

                let rotatingVerifier = try await AccessTokenVerifier(
                    verificationKeys: [
                        try primaryVerificationKey(),
                        try rotatedVerificationKey(),
                    ],
                    policy: primary.policy
                )

                let primaryToken = try await primary.issuer.issue(
                    systemIdentity: primary.systemIdentity,
                    session: primary.session,
                    client: primary.client,
                    tokenIdentifier: AccessTokenIdentifier(
                        "token-primary-key"
                    )
                )

                let rotatedToken = try await rotatedIssuer.issue(
                    systemIdentity: primary.systemIdentity,
                    session: primary.session,
                    client: primary.client,
                    tokenIdentifier: AccessTokenIdentifier(
                        "token-rotated-key"
                    )
                )

                let primaryClaims = try await rotatingVerifier.verify(
                    primaryToken
                )

                let rotatedClaims = try await rotatingVerifier.verify(
                    rotatedToken
                )

                try Expect.equal(
                    primaryClaims.tokenIdentifier,
                    try AccessTokenIdentifier(
                        "token-primary-key"
                    ),
                    "access-token.rotation.primary"
                )

                try Expect.equal(
                    rotatedClaims.tokenIdentifier,
                    try AccessTokenIdentifier(
                        "token-rotated-key"
                    ),
                    "access-token.rotation.rotated"
                )
            }
        }
    }
}

private struct AccessTokenFixture:
    Sendable
{
    let policy: AccessTokenPolicy
    let issuer: AccessTokenIssuer
    let verifier: AccessTokenVerifier

    let systemIdentity: SystemIdentityIdentifier
    let session: SessionIdentifier
    let client: ClientIdentifier
    let scopes: Set<AuthorizationScope>
}

private func accessTokenFixture() async throws -> AccessTokenFixture {
    let policy = try AccessTokenPolicy(
        issuer: AccessTokenIssuerIdentifier(
            "https://auth.depaix.systems"
        ),
        audience: AccessTokenAudienceIdentifier(
            "api.depaix.systems"
        ),
        lifetimeSeconds: 300
    )

    let issuer = try await AccessTokenIssuer(
        signingKey: primarySigningKey(),
        policy: policy
    )

    let verifier = try await AccessTokenVerifier(
        verificationKeys: [
            primaryVerificationKey(),
        ],
        policy: policy
    )

    return AccessTokenFixture(
        policy: policy,
        issuer: issuer,
        verifier: verifier,
        systemIdentity: try SystemIdentityIdentifier(
            "45b788e8-8078-4a94-9f56-e1ddba460d28"
        ),
        session: try SessionIdentifier(
            "6873abe1-e093-4323-9791-98de24e0f918"
        ),
        client: try ClientIdentifier(
            "client:test-api"
        ),
        scopes: [
            try AuthorizationScope(
                "records:read"
            ),
            try AuthorizationScope(
                "records:write"
            ),
        ]
    )
}

private func roundedNow() -> Date {
    Date(
        timeIntervalSince1970: floor(
            Date().timeIntervalSince1970
        )
    )
}

private func tamperPayload(
    _ token: AccessToken
) throws -> AccessToken {
    var components = token.encoded
        .split(
            separator: ".",
            omittingEmptySubsequences: false
        )
        .map(String.init)

    guard components.count == 3 else {
        throw AccessTokenError.invalidToken
    }

    var payload = components[1]

    guard let last = payload.popLast() else {
        throw AccessTokenError.invalidToken
    }

    payload.append(
        last == "A"
            ? "B"
            : "A"
    )

    components[1] = payload

    return try AccessToken(
        components.joined(
            separator: "."
        )
    )
}

private func primarySigningKey() throws -> AccessTokenSigningKey {
    try AccessTokenSigningKey(
        identifier: AccessTokenKeyIdentifier(
            "auth-test-primary"
        ),
        privateKeyPEM: primaryPrivateKeyPEM
    )
}

private func primaryVerificationKey() throws -> AccessTokenVerificationKey {
    try AccessTokenVerificationKey(
        identifier: AccessTokenKeyIdentifier(
            "auth-test-primary"
        ),
        publicKeyPEM: primaryPublicKeyPEM
    )
}

private func rotatedSigningKey() throws -> AccessTokenSigningKey {
    try AccessTokenSigningKey(
        identifier: AccessTokenKeyIdentifier(
            "auth-test-rotated"
        ),
        privateKeyPEM: rotatedPrivateKeyPEM
    )
}

private func rotatedVerificationKey() throws -> AccessTokenVerificationKey {
    try AccessTokenVerificationKey(
        identifier: AccessTokenKeyIdentifier(
            "auth-test-rotated"
        ),
        publicKeyPEM: rotatedPublicKeyPEM
    )
}

private let primaryPrivateKeyPEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMh5X0M3qRTra62fccbjPirzgTrrldER2+wDvoS1J0/UoAoGCCqGSM49
AwEHoUQDQgAE2XPUh8nAqh1dG7e52X4zuKB7BHoxlASqlkBeijgo4LEMZj2smXUi
e3KTjCUMMunYtbu+dLIcdgUVRzrX0wje9g==
-----END EC PRIVATE KEY-----
"""

private let primaryPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2XPUh8nAqh1dG7e52X4zuKB7BHox
lASqlkBeijgo4LEMZj2smXUie3KTjCUMMunYtbu+dLIcdgUVRzrX0wje9g==
-----END PUBLIC KEY-----
"""

private let rotatedPrivateKeyPEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICExcQtxSGnHAEdC+KI15CYD3hRRCCIZL0KQEPMg/0tDoAoGCCqGSM49
AwEHoUQDQgAEFz8qpsKu4tEPFDH0tG36YS3sdeVXWUIE7u3bV2hT1ZoB9mwGlE55
EJv/N4iuzW1SblE5nuDFM7paqeHb4tQRYA==
-----END EC PRIVATE KEY-----
"""

private let rotatedPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFz8qpsKu4tEPFDH0tG36YS3sdeVX
WUIE7u3bV2hT1ZoB9mwGlE55EJv/N4iuzW1SblE5nuDFM7paqeHb4tQRYA==
-----END PUBLIC KEY-----
"""
