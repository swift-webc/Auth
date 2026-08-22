import Foundation

public protocol ScopedAuthority:
    Sendable
{
    var scopes:
        Set<AuthorizationScope>
    { get }
}

public extension ScopedAuthority {
    func grants(
        _ scope:
            AuthorizationScope
    ) -> Bool {
        scopes.contains(
            scope
        )
    }

    func grants(
        all required:
            Set<AuthorizationScope>
    ) -> Bool {
        required.isSubset(
            of:
                scopes
        )
    }

    func require(
        _ scope:
            AuthorizationScope
    ) throws {
        try require(
            all: [
                scope,
            ]
        )
    }

    func require(
        all required:
            Set<AuthorizationScope>
    ) throws {
        let missing =
            required.subtracting(
                scopes
            )

        guard missing.isEmpty else {
            throw AuthorizationError
                .missing_scopes(
                    missing
                )
        }
    }
}

public enum AuthorizationError:
    Error,
    LocalizedError,
    Sendable,
    Equatable
{
    case missing_scopes(
        Set<AuthorizationScope>
    )

    public var errorDescription:
        String?
    {
        switch self {
        case .missing_scopes(
            let scopes
        ):
            let values =
                scopes
                    .map(\.rawValue)
                    .sorted()
                    .joined(
                        separator:
                            ", "
                    )

            return """
            Missing required authorization scopes: \(values).
            """
        }
    }
}
