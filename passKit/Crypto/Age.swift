import AgeKit
import Foundation

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

    /// Returns the public key for this identity.
    public func getPublicKey() -> String {
        identity.recipient.string
    }

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
        let ageRecipient: AgeKit.Age.X25519Recipient
        do {
            ageRecipient = try AgeKit.Age.X25519Recipient(recipient)
        } catch {
            throw AppError.agePublicKeyNotFound(keyID: recipient)
        }

        var outputStream = OutputStream.toMemory()
        outputStream.open()
        defer { outputStream.close() }

        var writer = try AgeKit.Age.encrypt(dst: &outputStream, recipients: ageRecipient)

        var mutableData = plainData
        _ = try writer.write(&mutableData)
        try writer.close()

        guard let encryptedData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw AppError.encryption
        }

        return encryptedData
    }

    /// Resolves the recipient for a password at the given path by searching for `.age-recipients` files
    /// up the directory tree, falling back to this identity's public key.
    func getRecipient(from path: String) -> String? {
        if let recipient = findAgeRecipient(for: path) {
            return recipient
        }
        return getPublicKey()
    }

    private func findAgeRecipient(for path: String) -> String? {
        let storeURL = Globals.repositoryURL
        var currentPath = (path as NSString).deletingLastPathComponent

        while !currentPath.isEmpty {
            let recipientsFile = storeURL
                .appendingPathComponent(currentPath)
                .appendingPathComponent(".age-recipients")

            if let recipient = readFirstRecipient(from: recipientsFile) {
                return recipient
            }

            currentPath = (currentPath as NSString).deletingLastPathComponent
        }

        let rootRecipientsFile = storeURL.appendingPathComponent(".age-recipients")
        return readFirstRecipient(from: rootRecipientsFile)
    }

    private func readFirstRecipient(from fileURL: URL) -> String? {
        guard let contents = try? String(contentsOf: fileURL, encoding: .utf8) else {
            return nil
        }

        return contents.splitByNewline()
            .first { !$0.isEmpty && !$0.hasPrefix("#") }?
            .trimmed
    }
}
