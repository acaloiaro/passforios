import AgeKit
import CryptoKit
import Foundation

/// A composite AgeKit Recipient that wraps multiple recipients into one,
/// working around AgeKit's variadic-only encrypt API.
private struct CompositeRecipient: AgeKit.Recipient {
    let recipients: [AgeKit.Recipient]

    func wrap(fileKey: SymmetricKey) throws -> [AgeKit.Age.Stanza] {
        try recipients.flatMap { try $0.wrap(fileKey: fileKey) }
    }
}

public struct Age: EncryptionInterface {
    public static let publicKeyPrefix = "age1"
    public static let privateKeyPrefix = "AGE-SECRET-KEY-1"
    private static let maxDecryptedSize = 1024 * 1024

    private let identity: AgeKit.Age.X25519Identity

    init(identity: AgeKit.Age.X25519Identity) {
        self.identity = identity
    }

    /// Parse an Age identity from a private key string.
    public static func parseIdentity(from privateKeyString: String) throws -> AgeKit.Age.X25519Identity {
        guard let keyData = privateKeyString.data(using: .utf8) else {
            throw AppError.agePrivateKeyNotFound(keyID: "default")
        }
        let inputStream = InputStream(data: keyData)
        inputStream.open()
        defer { inputStream.close() }

        let identities = try AgeKit.Age.parseIdentities(input: inputStream)
        guard let identity = identities.first as? AgeKit.Age.X25519Identity else {
            throw AppError.agePrivateKeyNotFound(keyID: "default")
        }
        return identity
    }

    /// Derive the Bech32-encoded public key (age1...) from a private key string.
    public static func derivePublicKey(from privateKeyString: String) throws -> String {
        let identity = try parseIdentity(from: privateKeyString)
        return identity.recipient.string
    }

    var recipientsFilename: String { ".age-recipients" }

    /// Returns the public key for this identity.
    public func getPublicKey() -> String {
        identity.recipient.string
    }

    func containsRecipient(_ recipient: String) -> Bool {
        recipient == getPublicKey()
    }

    var fallbackRecipient: String? { getPublicKey() }

    func decrypt(encryptedData: Data) throws -> Data? {
        let inputStream = InputStream(data: encryptedData)
        inputStream.open()
        defer { inputStream.close() }

        var reader: AgeKit.StreamReader
        do {
            reader = try AgeKit.Age.decrypt(src: inputStream, identities: identity)
        } catch is AgeKit.Age.DecryptError {
            throw AppError.decryptionKeyMismatch
        }

        // AgeKit's StreamReader signals EOF by throwing rather than returning 0
        var buf = Data(repeating: 0, count: 65536)
        var result = Data()

        do {
            while true {
                let bytesRead = try reader.read(&buf)
                result.append(buf.prefix(bytesRead))

                guard result.count <= Self.maxDecryptedSize else {
                    throw AppError.decryptionSizeExceeded
                }
            }
        } catch {
            if result.isEmpty {
                throw error
            }
        }

        return result
    }

    func encrypt(plainData: Data, recipient: String) throws -> Data {
        try encrypt(plainData: plainData, recipients: [recipient])
    }

    func encrypt(plainData: Data, recipients: [String]) throws -> Data {
        guard !recipients.isEmpty else {
            throw AppError.encryption
        }

        let ageRecipients: [AgeKit.Age.X25519Recipient] = try recipients.map { key in
            do {
                return try AgeKit.Age.X25519Recipient(key)
            } catch {
                throw AppError.agePublicKeyNotFound(keyID: key)
            }
        }

        var outputStream = OutputStream.toMemory()
        outputStream.open()
        defer { outputStream.close() }

        let composite = CompositeRecipient(recipients: ageRecipients)
        var writer = try AgeKit.Age.encrypt(dst: &outputStream, recipients: composite)

        var mutableData = plainData
        _ = try writer.write(&mutableData)
        try writer.close()

        guard let encryptedData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw AppError.encryption
        }

        return encryptedData
    }
}
