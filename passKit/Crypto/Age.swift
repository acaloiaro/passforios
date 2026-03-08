import AgeKit
import Foundation

struct Age: EncryptionInterface {
    private let identity: AgeKit.Age.X25519Identity

    init(identity: AgeKit.Age.X25519Identity) {
        self.identity = identity
    }

    func decrypt(encryptedData: Data) throws -> Data? {
        // Use AgeKit stream-based API for decryption
        let inputStream = InputStream(data: encryptedData)
        inputStream.open()
        defer { inputStream.close() }

        // Decrypt using the identity
        var reader = try AgeKit.Age.decrypt(src: inputStream, identities: identity)

        // Read all decrypted data
        // AgeKit's StreamReader throws at EOF rather than returning 0
        var buf = Data(repeating: 0, count: 65536)
        var result = Data()

        do {
            while true {
                let bytesRead = try reader.read(&buf)
                result.append(buf.prefix(bytesRead))
            }
        } catch {
            // AgeKit signals end-of-stream by throwing from read()
            if result.isEmpty {
                throw error
            }
        }

        return result
    }

    func encrypt(plainData: Data, recipient: String) throws -> Data {
        // Parse recipient from Bech32 string (age1... format)
        let ageRecipient: AgeKit.Age.X25519Recipient
        do {
            ageRecipient = try AgeKit.Age.X25519Recipient(recipient)
        } catch {
            throw AppError.agePublicKeyNotFound(keyID: recipient)
        }

        // Use AgeKit stream-based API for encryption
        var outputStream = OutputStream.toMemory()
        outputStream.open()
        defer { outputStream.close() }

        var writer = try AgeKit.Age.encrypt(dst: &outputStream, recipients: ageRecipient)

        // Write plaintext data
        var mutableData = plainData
        _ = try writer.write(&mutableData)

        // Close the writer to finalize encryption
        try writer.close()

        // Extract encrypted data from memory stream
        guard let encryptedData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw AppError.encryption
        }

        return encryptedData
    }

    func getRecipient(from path: String) -> String? {
        // Try to find .age-recipients file in directory hierarchy
        if let recipient = findAgeRecipient(for: path) {
            return recipient
        }

        // Fall back to default global Age public key from Keychain
        return AppKeychain.shared.get(for: AgeKey.PUBLIC.getKeychainKey())
    }

    private func findAgeRecipient(for path: String) -> String? {
        let storeURL = Globals.repositoryURL
        var currentPath = (path as NSString).deletingLastPathComponent

        // Traverse up the directory tree looking for .age-recipients file
        while !currentPath.isEmpty {
            let recipientsFile = storeURL
                .appendingPathComponent(currentPath)
                .appendingPathComponent(".age-recipients")

            if let recipient = readFirstRecipient(from: recipientsFile) {
                return recipient
            }

            currentPath = (currentPath as NSString).deletingLastPathComponent
        }

        // Check root .age-recipients file
        let rootRecipientsFile = storeURL.appendingPathComponent(".age-recipients")
        return readFirstRecipient(from: rootRecipientsFile)
    }

    private func readFirstRecipient(from fileURL: URL) -> String? {
        guard FileManager.default.fileExists(atPath: fileURL.path),
              let contents = try? String(contentsOf: fileURL, encoding: .utf8) else {
            return nil
        }

        // Return first non-empty, non-comment line
        let lines = contents.components(separatedBy: .newlines)
        return lines
            .first { !$0.isEmpty && !$0.hasPrefix("#") }?
            .trimmingCharacters(in: .whitespaces)
    }
}
