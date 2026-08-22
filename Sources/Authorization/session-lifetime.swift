import Foundation

public enum SessionStatus:
    String,
    Sendable,
    Codable,
    Hashable
{
    case active
    case idle_expired
    case absolute_expired
    case revoked
}

public enum SessionLifetimeError:
    Error,
    LocalizedError,
    Sendable,
    Equatable
{
    case invalid_policy
    case invalid_timeline
    case inactive_session

    public var errorDescription:
        String?
    {
        switch self {
        case .invalid_policy:
            return """
            The session lifetime policy is invalid.
            """

        case .invalid_timeline:
            return """
            The session lifetime timeline is invalid.
            """

        case .inactive_session:
            return """
            The session is no longer active.
            """
        }
    }
}

public struct SessionLifetimePolicy:
    Sendable,
    Codable,
    Hashable
{
    public let idleLifetime:
        TimeInterval?

    public let absoluteLifetime:
        TimeInterval

    public init(
        idleLifetime:
            TimeInterval? = nil,
        absoluteLifetime:
            TimeInterval
    ) throws {
        guard
            absoluteLifetime.isFinite,
            absoluteLifetime > 0
        else {
            throw SessionLifetimeError
                .invalid_policy
        }

        if let idleLifetime {
            guard
                idleLifetime.isFinite,
                idleLifetime > 0
            else {
                throw SessionLifetimeError
                    .invalid_policy
            }
        }

        self.idleLifetime =
            idleLifetime

        self.absoluteLifetime =
            absoluteLifetime
    }

    public func makeLifetime(
        startingAt createdAt:
            Date = Date()
    ) throws -> SessionLifetime {
        let absoluteExpiresAt =
            createdAt.addingTimeInterval(
                absoluteLifetime
            )

        let idleExpiresAt =
            idleLifetime.map { lifetime in
                min(
                    createdAt.addingTimeInterval(
                        lifetime
                    ),
                    absoluteExpiresAt
                )
            }

        return try SessionLifetime(
            createdAt:
                createdAt,
            lastActivityAt:
                createdAt,
            idleExpiresAt:
                idleExpiresAt,
            absoluteExpiresAt:
                absoluteExpiresAt,
            revokedAt:
                nil
        )
    }

    public func refreshing(
        _ lifetime:
            SessionLifetime,
        at activityAt:
            Date = Date()
    ) throws -> SessionLifetime {
        guard
            lifetime.status(
                at:
                    activityAt
            ) == .active
        else {
            throw SessionLifetimeError
                .inactive_session
        }

        guard
            activityAt
                >= lifetime.lastActivityAt
        else {
            throw SessionLifetimeError
                .invalid_timeline
        }

        let idleExpiresAt =
            idleLifetime.map { lifetimeSeconds in
                min(
                    activityAt.addingTimeInterval(
                        lifetimeSeconds
                    ),
                    lifetime.absoluteExpiresAt
                )
            }

        return try SessionLifetime(
            createdAt:
                lifetime.createdAt,
            lastActivityAt:
                activityAt,
            idleExpiresAt:
                idleExpiresAt,
            absoluteExpiresAt:
                lifetime.absoluteExpiresAt,
            revokedAt:
                lifetime.revokedAt
        )
    }
}

public struct SessionLifetime:
    Sendable,
    Codable,
    Hashable
{
    public let createdAt:
        Date

    public let lastActivityAt:
        Date

    public let idleExpiresAt:
        Date?

    public let absoluteExpiresAt:
        Date

    public let revokedAt:
        Date?

    public init(
        createdAt:
            Date,
        lastActivityAt:
            Date,
        idleExpiresAt:
            Date?,
        absoluteExpiresAt:
            Date,
        revokedAt:
            Date?
    ) throws {
        guard
            lastActivityAt >= createdAt,
            absoluteExpiresAt > createdAt,
            lastActivityAt <= absoluteExpiresAt
        else {
            throw SessionLifetimeError
                .invalid_timeline
        }

        if let idleExpiresAt {
            guard
                idleExpiresAt
                    >= lastActivityAt,
                idleExpiresAt
                    <= absoluteExpiresAt
            else {
                throw SessionLifetimeError
                    .invalid_timeline
            }
        }

        if let revokedAt {
            guard
                revokedAt >= createdAt
            else {
                throw SessionLifetimeError
                    .invalid_timeline
            }
        }

        self.createdAt =
            createdAt

        self.lastActivityAt =
            lastActivityAt

        self.idleExpiresAt =
            idleExpiresAt

        self.absoluteExpiresAt =
            absoluteExpiresAt

        self.revokedAt =
            revokedAt
    }

    public func status(
        at date:
            Date = Date()
    ) -> SessionStatus {
        if
            let revokedAt,
            revokedAt <= date
        {
            return .revoked
        }

        if date >= absoluteExpiresAt {
            return .absolute_expired
        }

        if
            let idleExpiresAt,
            date >= idleExpiresAt
        {
            return .idle_expired
        }

        return .active
    }

    public func revoking(
        at revokedAt:
            Date = Date()
    ) throws -> Self {
        guard revokedAt >= createdAt else {
            throw SessionLifetimeError
                .invalid_timeline
        }

        return try Self(
            createdAt:
                createdAt,
            lastActivityAt:
                lastActivityAt,
            idleExpiresAt:
                idleExpiresAt,
            absoluteExpiresAt:
                absoluteExpiresAt,
            revokedAt:
                revokedAt
        )
    }
}
