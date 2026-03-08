//
//  GopenPGPInterface.swift
//  passKit
//
//  Created by Danny Moesch on 08.09.19.
//  Copyright © 2019 Bob Sun. All rights reserved.
//

import Gopenpgp

struct GopenPGPInterface: PGPInterface {
    private static let errorMapping: [String: Error] = [
        "gopenpgp: error in unlocking key: openpgp: invalid data: private key checksum failure": AppError.wrongPassphrase,
        "gopenpgp: error in reading message: openpgp: incorrect key": AppError.keyExpiredOrIncompatible,
    ]

    private var publicKeys: [String: CryptoKey] = [:]
    private var privateKeys: [String: CryptoKey] = [:]

    init(publicArmoredKey: String, privateArmoredKey: String) throws {
        let pubKeys = extractKeysFromArmored(str: publicArmoredKey)
        let prvKeys = extractKeysFromArmored(str: privateArmoredKey)

        for key in pubKeys {
            var error: NSError?
            guard let cryptoKey = CryptoNewKeyFromArmored(key, &error) else {
                guard error == nil else {
                    throw error!
                }
                throw AppError.keyImport
            }
            publicKeys[cryptoKey.getFingerprint().lowercased()] = cryptoKey
        }

        for key in prvKeys {
            var error: NSError?
            guard let cryptoKey = CryptoNewKeyFromArmored(key, &error) else {
                guard error == nil else {
                    throw error!
                }
                throw AppError.keyImport
            }
            privateKeys[cryptoKey.getFingerprint().lowercased()] = cryptoKey
        }
    }

    func extractKeysFromArmored(str: String) -> [String] {
        var keys: [String] = []
        var key = ""
        for line in str.splitByNewline() {
            if line.trimmed.uppercased().hasPrefix("-----BEGIN PGP") {
                key = ""
                key += line
            } else if line.trimmed.uppercased().hasPrefix("-----END PGP") {
                key += line
                keys.append(key)
            } else {
                key += line
            }
            key += "\n"
        }
        return keys
    }

    func containsPublicKey(with keyID: String) -> Bool {
        publicKeys.keys.contains { key in key.hasSuffix(keyID.lowercased()) }
    }

    func containsPrivateKey(with keyID: String) -> Bool {
        privateKeys.keys.contains { key in key.hasSuffix(keyID.lowercased()) }
    }

    func decrypt(encryptedData: Data) throws -> Data? {
        // Here we assume that the passphrase is empty.
        // The passphrase will be provided by the UI.
        try decrypt(encryptedData: encryptedData, passphrase: "")
    }

    func decrypt(encryptedData: Data, passphrase: String) throws -> Data? {
        guard !privateKeys.isEmpty else {
            throw AppError.decryption
        }

        var lastError: Error = AppError.decryption
        for (_, privateKey) in privateKeys {
            do {
                var isLocked: ObjCBool = false
                try privateKey.isLocked(&isLocked)
                var unlockedKey: CryptoKey!
                if isLocked.boolValue {
                    unlockedKey = try privateKey.unlock(passphrase.data(using: .utf8))
                } else {
                    unlockedKey = privateKey
                }
                var error: NSError?

                guard let keyRing = CryptoNewKeyRing(unlockedKey, &error) else {
                    if let error {
                        throw error
                    }
                    throw AppError.decryption
                }

                let message = createPGPMessage(from: encryptedData)
                return try keyRing.decrypt(message, verifyKey: nil, verifyTime: 0).data
            } catch {
                lastError = error
                continue
            }
        }
        throw Self.errorMapping[lastError.localizedDescription, default: lastError]
    }

    func encrypt(plainData: Data, recipient: String) throws -> Data {
        let key: CryptoKey? = publicKeys.first(where: { key, _ in key.hasSuffix(recipient.lowercased()) })?.value

        guard let publicKey = key else {
            throw AppError.encryption
        }

        var error: NSError?

        guard let keyRing = CryptoNewKeyRing(publicKey, &error) else {
            guard error == nil else {
                throw error!
            }
            throw AppError.encryption
        }

        let encryptedData = try keyRing.encrypt(CryptoNewPlainMessage(plainData.mutable as Data), privateKey: nil)
        if Defaults.encryptInArmored {
            var error: NSError?
            let armor = encryptedData.getArmored(&error)
            guard error == nil else {
                throw error!
            }
            return armor.data(using: .ascii)!
        }
        return encryptedData.getBinary()!
    }

    func getRecipient(from path: String) -> String? {
        if let recipient = findGPGID(for: path) {
            return recipient
        }
        return publicKeys.keys.first
    }

    private func findGPGID(for path: String) -> String? {
        let storeURL = Globals.repositoryURL
        var currentPath = (path as NSString).deletingLastPathComponent

        while !currentPath.isEmpty {
            let gpgIDFile = storeURL
                .appendingPathComponent(currentPath)
                .appendingPathComponent(".gpg-id")

            let recipients = readRecipients(from: gpgIDFile)
            if let match = matchingRecipient(from: recipients) {
                return match
            }

            currentPath = (currentPath as NSString).deletingLastPathComponent
        }

        let rootGPGIDFile = storeURL.appendingPathComponent(".gpg-id")
        let recipients = readRecipients(from: rootGPGIDFile)
        return matchingRecipient(from: recipients)
    }

    private func readRecipients(from fileURL: URL) -> [String] {
        guard let contents = try? String(contentsOf: fileURL, encoding: .utf8) else {
            return []
        }
        return contents.splitByNewline()
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            .map(\.trimmed)
    }

    private func matchingRecipient(from recipients: [String]) -> String? {
        if recipients.isEmpty {
            return nil
        }
        // Prefer a recipient for which we hold a private key (decryption)
        return recipients.first { containsPrivateKey(with: $0) }
            ?? recipients.first // fallback for encryption
    }

    var keyID: [String] {
        publicKeys.keys.map { $0.uppercased() }
    }

    var shortKeyID: [String] {
        publicKeys.keys.map { $0.suffix(8).uppercased() }
    }

    func decrypt(encryptedData: Data, keyID _: String?, passphrase: String) throws -> Data? {
        try decrypt(encryptedData: encryptedData, passphrase: passphrase)
    }

    func encrypt(plainData: Data, keyID: String?) throws -> Data {
        let recipient = keyID ?? publicKeys.keys.first ?? ""
        return try encrypt(plainData: plainData, recipient: recipient)
    }
}

public func createPGPMessage(from encryptedData: Data) -> CryptoPGPMessage? {
    // Important note:
    // Even if Defaults.encryptInArmored is true now, it could be different during the encryption.
    var error: NSError?
    let message = CryptoNewPGPMessageFromArmored(String(data: encryptedData, encoding: .ascii), &error)
    if error == nil {
        return message
    }
    return CryptoNewPGPMessage(encryptedData.mutable as Data)
}
