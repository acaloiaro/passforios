import Foundation

protocol EncryptionInterface {
    var recipientsFilename: String { get }

    func decrypt(encryptedData: Data) throws -> Data?

    func encrypt(plainData: Data, recipient: String) throws -> Data

    func encrypt(plainData: Data, recipients: [String]) throws -> Data

    func containsRecipient(_ recipient: String) -> Bool

    /// Fallback recipient when no recipients file is found in the directory tree.
    var fallbackRecipient: String? { get }
}

extension EncryptionInterface {
    func recipients(fromFileAt url: URL) -> [String] {
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        return contents.splitByNewline()
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            .map(\.trimmed)
    }

    func findRecipients(for path: String) -> [String] {
        let storeURL = Globals.repositoryURL
        var currentPath = (path as NSString).deletingLastPathComponent

        while !currentPath.isEmpty {
            let recipientsFile = storeURL
                .appendingPathComponent(currentPath)
                .appendingPathComponent(recipientsFilename)

            let found = recipients(fromFileAt: recipientsFile)
            if !found.isEmpty {
                return found
            }

            currentPath = (currentPath as NSString).deletingLastPathComponent
        }

        let rootFile = storeURL.appendingPathComponent(recipientsFilename)
        return recipients(fromFileAt: rootFile)
    }

    func encrypt(plainData: Data, recipients: [String]) throws -> Data {
        guard let recipient = recipients.first else {
            throw AppError.encryption
        }
        return try encrypt(plainData: plainData, recipient: recipient)
    }

    func getRecipients(from path: String) -> [String] {
        let allRecipients = findRecipients(for: path)
        if allRecipients.isEmpty, let fallback = fallbackRecipient {
            return [fallback]
        }
        return allRecipients
    }

    func getRecipient(from path: String) -> String? {
        let allRecipients = findRecipients(for: path)
        if allRecipients.isEmpty {
            return fallbackRecipient
        }
        return allRecipients.first(where: { containsRecipient($0) })
            ?? allRecipients.first
    }
}
