import Foundation

public struct AccessTokenSigningKey:
    Sendable,
    Equatable
{
    public let identifier: AccessTokenKeyIdentifier
    public let privateKeyPEM: String

    public init(
        identifier: AccessTokenKeyIdentifier,
        privateKeyPEM: String
    ) throws {
        let privateKeyPEM = privateKeyPEM.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        guard !privateKeyPEM.isEmpty else {
            throw AccessTokenError.invalidKey
        }

        self.identifier = identifier
        self.privateKeyPEM = privateKeyPEM
    }
}

public struct AccessTokenVerificationKey:
    Sendable,
    Equatable
{
    public let identifier: AccessTokenKeyIdentifier
    public let publicKeyPEM: String

    public init(
        identifier: AccessTokenKeyIdentifier,
        publicKeyPEM: String
    ) throws {
        let publicKeyPEM = publicKeyPEM.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        guard !publicKeyPEM.isEmpty else {
            throw AccessTokenError.invalidKey
        }

        self.identifier = identifier
        self.publicKeyPEM = publicKeyPEM
    }
}
