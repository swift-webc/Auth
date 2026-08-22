public struct PasswordHash:
    Sendable,
    Hashable,
    Codable
{
    /// Self-contained Argon2id PHC string suitable for database storage.
    public let encoded: String

    public init(
        _ encoded: String
    ) throws {
        guard Self.isSupported(encoded) else {
            throw PasswordError.invalidEncodedHash
        }

        self.encoded = encoded
    }

    public init(
        from decoder: Decoder
    ) throws {
        let container = try decoder.singleValueContainer()
        let encoded = try container.decode(String.self)

        do {
            try self.init(encoded)
        } catch {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid or unsupported encoded password hash."
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

private extension PasswordHash {
    static func isSupported(
        _ encoded: String
    ) -> Bool {
        let bytes = Array(encoded.utf8)

        guard
            !bytes.isEmpty,
            bytes.count <= 127,
            bytes.allSatisfy({ byte in
                (0x21...0x7E).contains(byte)
            })
        else {
            return false
        }

        let parts = encoded.split(
            separator: "$",
            omittingEmptySubsequences: false
        )

        guard
            parts.count == 6,
            parts[0].isEmpty,
            parts[1] == "argon2id",
            parts[2] == "v=19"
        else {
            return false
        }

        let parameters = parts[3].split(
            separator: ",",
            omittingEmptySubsequences: false
        )

        guard
            parameters.count == 3,
            positiveValue(
                parameters[0],
                prefix: "m="
            ) != nil,
            positiveValue(
                parameters[1],
                prefix: "t="
            ) != nil,
            positiveValue(
                parameters[2],
                prefix: "p="
            ) != nil,
            isUnpaddedBase64(parts[4]),
            isUnpaddedBase64(parts[5])
        else {
            return false
        }

        return true
    }

    static func positiveValue(
        _ component: Substring,
        prefix: String
    ) -> Int? {
        guard component.hasPrefix(prefix) else {
            return nil
        }

        let rawValue = component.dropFirst(
            prefix.count
        )

        guard
            let value = Int(rawValue),
            value > 0
        else {
            return nil
        }

        return value
    }

    static func isUnpaddedBase64(
        _ value: Substring
    ) -> Bool {
        guard !value.isEmpty else {
            return false
        }

        return value.utf8.allSatisfy { byte in
            switch byte {
            case 0x30...0x39,
                 0x41...0x5A,
                 0x61...0x7A,
                 0x2B,
                 0x2F:
                return true

            default:
                return false
            }
        }
    }
}
