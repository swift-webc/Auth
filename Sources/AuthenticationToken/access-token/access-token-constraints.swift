import Authorization
import Authentication
import Foundation

public struct AccessTokenConstraints:
    Sendable,
    Equatable
{
    public struct Required:
        Sendable,
        Equatable
    {
        public let scopes: Set<AuthorizationScope>
        public let methods: Set<AuthenticationMethod>
        public let assurances: Set<AuthenticationAssurance>

        public init(
            scopes: Set<AuthorizationScope> = [],
            methods: Set<AuthenticationMethod> = [],
            assurances: Set<AuthenticationAssurance> = []
        ) {
            self.scopes = scopes
            self.methods = methods
            self.assurances = assurances
        }
    }

    public struct Allowed:
        Sendable,
        Equatable
    {
        public let clients: Set<ClientIdentifier>?

        public init(
            clients: Set<ClientIdentifier>? = nil
        ) {
            self.clients = clients
        }
    }

    public struct Maximum:
        Sendable,
        Equatable
    {
        public let authenticationAge: TimeInterval?

        init(
            authenticationAge: TimeInterval?
        ) {
            self.authenticationAge = authenticationAge
        }
    }

    public enum Violation:
        Sendable,
        Equatable
    {
        case missing_scopes(
            Set<AuthorizationScope>
        )

        case client_not_allowed(
            ClientIdentifier
        )

        case missing_authentication_methods(
            Set<AuthenticationMethod>
        )

        case missing_assurances(
            Set<AuthenticationAssurance>
        )

        case authentication_too_old(
            maximumAge: TimeInterval,
            actualAge: TimeInterval
        )

        case authentication_time_in_future
    }

    public struct Evaluation:
        Sendable,
        Equatable
    {
        public let violations: [Violation]

        public var isSatisfied: Bool {
            violations.isEmpty
        }
    }

    public let required: Required
    public let allowed: Allowed
    public let maximum: Maximum

    public init(
        required: Required = .init(),
        allowed: Allowed = .init()
    ) {
        self.required = required
        self.allowed = allowed
        self.maximum = Maximum(
            authenticationAge: nil
        )
    }

    public init(
        required: Required = .init(),
        allowed: Allowed = .init(),
        maximumAuthenticationAge: TimeInterval
    ) throws {
        guard
            maximumAuthenticationAge.isFinite,
            maximumAuthenticationAge > 0
        else {
            throw AccessTokenError.invalidConstraints
        }

        self.required = required
        self.allowed = allowed
        self.maximum = Maximum(
            authenticationAge:
                maximumAuthenticationAge
        )
    }

    public func evaluate(
        _ claims: AccessTokenClaims,
        at now: Date = Date()
    ) -> Evaluation {
        var violations: [Violation] = []

        let missingScopes =
            required.scopes.subtracting(
                claims.scopes
            )

        if !missingScopes.isEmpty {
            violations.append(
                .missing_scopes(
                    missingScopes
                )
            )
        }

        if
            let clients = allowed.clients,
            !clients.contains(
                claims.client
            )
        {
            violations.append(
                .client_not_allowed(
                    claims.client
                )
            )
        }

        let missingMethods =
            required.methods.subtracting(
                claims.authenticationMethods
            )

        if !missingMethods.isEmpty {
            violations.append(
                .missing_authentication_methods(
                    missingMethods
                )
            )
        }

        let missingAssurances =
            required.assurances.subtracting(
                claims.assurances
            )

        if !missingAssurances.isEmpty {
            violations.append(
                .missing_assurances(
                    missingAssurances
                )
            )
        }

        if let maximumAge =
            maximum.authenticationAge
        {
            let actualAge =
                now.timeIntervalSince(
                    claims.authenticatedAt
                )

            if actualAge < 0 {
                violations.append(
                    .authentication_time_in_future
                )
            } else if actualAge > maximumAge {
                violations.append(
                    .authentication_too_old(
                        maximumAge: maximumAge,
                        actualAge: actualAge
                    )
                )
            }
        }

        return Evaluation(
            violations: violations
        )
    }
}
