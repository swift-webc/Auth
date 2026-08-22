public struct AccessToken:
    Sendable,
    Codable,
    Hashable
{
    public let encoded: String

    public init(
        _ encoded: String
    ) throws {
        let parts = encoded.split(
            separator: ".",
            omittingEmptySubsequences: false
        )

        guard
            parts.count == 3,
            parts.allSatisfy({ part in
                !part.isEmpty && Self.isBase64URL(part)
            })
        else {
            throw AccessTokenError.invalidToken
        }

        self.encoded = encoded
    }

    public init(
        from decoder: Decoder
    ) throws {
        let container = try decoder.singleValueContainer()
        let encoded = try container.decode(
            String.self
        )

        do {
            try self.init(encoded)
        } catch {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid encoded access token."
            )
        }
    }

    public func encode(
        to encoder: Encoder
    ) throws {
        var container = encoder.singleValueContainer()

        try container.encode(
            encoded
        )
    }
}

private extension AccessToken {
    static func isBase64URL(
        _ value: Substring
    ) -> Bool {
        value.utf8.allSatisfy { byte in
            switch byte {
            case 0x30...0x39,
                 0x41...0x5A,
                 0x61...0x7A,
                 0x2D,
                 0x5F:
                return true

            default:
                return false
            }
        }
    }
}
