import Authentication
import Sodium

public struct PasswordAuthentication:
    Sendable
{
    public let policy: PasswordPolicy

    public init(
        policy: PasswordPolicy = .interactive
    ) {
        self.policy = policy
    }

    public func hash(
        _ password: String
    ) throws -> PasswordHash {
        let sodium = Sodium()
        var passwordBytes = Array(password.utf8)

        defer {
            sodium.utils.zero(
                &passwordBytes
            )
        }

        guard let encoded = sodium.pwHash.str(
            passwd: passwordBytes,
            opsLimit: policy.operations,
            memLimit: policy.memoryBytes
        ) else {
            throw PasswordError.hashingFailed
        }

        guard let hash = try? PasswordHash(encoded) else {
            throw PasswordError.hashingFailed
        }

        return hash
    }

    public func verify(
        _ password: String,
        against hash: PasswordHash
    ) -> PasswordVerification {
        let sodium = Sodium()
        var passwordBytes = Array(password.utf8)

        defer {
            sodium.utils.zero(
                &passwordBytes
            )
        }

        guard sodium.pwHash.strVerify(
            hash: hash.encoded,
            passwd: passwordBytes
        ) else {
            return .rejected
        }

        let rehash = sodium.pwHash.strNeedsRehash(
            hash: hash.encoded,
            opsLimit: policy.operations,
            memLimit: policy.memoryBytes
        )

        return .accepted(
            rehash: rehash
        )
    }
}
