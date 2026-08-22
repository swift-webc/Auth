import Sodium

public struct PasswordPolicy:
    Sendable,
    Equatable
{
    /// Computational work applied by Argon2id.
    public let operations: Int

    /// Maximum working memory used by Argon2id, expressed in bytes.
    public let memoryBytes: Int

    public init(
        operations: Int,
        memoryBytes: Int
    ) throws {
        guard
            operations > 0,
            memoryBytes > 0
        else {
            throw PasswordError.invalidPolicy
        }

        self.operations = operations
        self.memoryBytes = memoryBytes
    }

    /// Libsodium's interactive password-storage policy.
    ///
    /// This is the initial functional default. The production policy should
    /// later be benchmarked explicitly on the machine running central Auth.
    public static var interactive: Self {
        let passwordHashing = Sodium().pwHash

        return Self(
            uncheckedOperations: passwordHashing.OpsLimitInteractive,
            memoryBytes: passwordHashing.MemLimitInteractive
        )
    }

    private init(
        uncheckedOperations operations: Int,
        memoryBytes: Int
    ) {
        self.operations = operations
        self.memoryBytes = memoryBytes
    }
}
