import Authorization
import Authentication
import Foundation
import TestFlows

extension AuthenticationFlowSuite {
    static var sessionLifetimeFlow:
        TestFlow
    {
        TestFlow(
            "session-lifetime",
            tags: [
                "authentication",
                "authorization",
                "session",
                "lifetime",
            ]
        ) {
            Step(
                "new session is active"
            ) {
                let now =
                    Date(
                        timeIntervalSince1970:
                            1_800_000_000
                    )

                let policy =
                    try SessionLifetimePolicy(
                        idleLifetime:
                            300,
                        absoluteLifetime:
                            3_600
                    )

                let lifetime =
                    try policy.makeLifetime(
                        startingAt:
                            now
                    )

                try Expect.equal(
                    lifetime.status(
                        at:
                            now.addingTimeInterval(
                                299
                            )
                    ),
                    .active,
                    "session-lifetime.active"
                )

                try Expect.equal(
                    lifetime.status(
                        at:
                            now.addingTimeInterval(
                                300
                            )
                    ),
                    .idle_expired,
                    "session-lifetime.idle-expired"
                )
            }

            Step(
                "idle expiry is capped by absolute expiry"
            ) {
                let now =
                    Date(
                        timeIntervalSince1970:
                            1_800_000_000
                    )

                let policy =
                    try SessionLifetimePolicy(
                        idleLifetime:
                            7_200,
                        absoluteLifetime:
                            3_600
                    )

                let lifetime =
                    try policy.makeLifetime(
                        startingAt:
                            now
                    )

                try Expect.equal(
                    lifetime.idleExpiresAt,
                    lifetime.absoluteExpiresAt,
                    "session-lifetime.idle-cap"
                )

                try Expect.equal(
                    lifetime.status(
                        at:
                            now.addingTimeInterval(
                                3_600
                            )
                    ),
                    .absolute_expired,
                    "session-lifetime.absolute-expired"
                )
            }

            Step(
                "activity refreshes idle expiry without extending absolute expiry"
            ) {
                let now =
                    Date(
                        timeIntervalSince1970:
                            1_800_000_000
                    )

                let policy =
                    try SessionLifetimePolicy(
                        idleLifetime:
                            300,
                        absoluteLifetime:
                            3_600
                    )

                let initial =
                    try policy.makeLifetime(
                        startingAt:
                            now
                    )

                let refreshed =
                    try policy.refreshing(
                        initial,
                        at:
                            now.addingTimeInterval(
                                120
                            )
                    )

                try Expect.equal(
                    refreshed.lastActivityAt,
                    now.addingTimeInterval(
                        120
                    ),
                    "session-lifetime.refresh.activity"
                )

                try Expect.equal(
                    refreshed.idleExpiresAt,
                    now.addingTimeInterval(
                        420
                    ),
                    "session-lifetime.refresh.idle"
                )

                try Expect.equal(
                    refreshed.absoluteExpiresAt,
                    initial.absoluteExpiresAt,
                    "session-lifetime.refresh.absolute"
                )
            }

            Step(
                "revocation changes session state"
            ) {
                let now =
                    Date(
                        timeIntervalSince1970:
                            1_800_000_000
                    )

                let policy =
                    try SessionLifetimePolicy(
                        absoluteLifetime:
                            3_600
                    )

                let lifetime =
                    try policy.makeLifetime(
                        startingAt:
                            now
                    )

                let revokedAt =
                    now.addingTimeInterval(
                        30
                    )

                let revoked =
                    try lifetime.revoking(
                        at:
                            revokedAt
                    )

                try Expect.equal(
                    revoked.status(
                        at:
                            revokedAt
                    ),
                    .revoked,
                    "session-lifetime.revoked"
                )
            }

            Step(
                "invalid lifetime policy is rejected"
            ) {
                try Expect.throwsError(
                    "session-lifetime.invalid-policy"
                ) {
                    _ =
                        try SessionLifetimePolicy(
                            absoluteLifetime:
                                0
                        )
                }
            }
        }
    }
}
