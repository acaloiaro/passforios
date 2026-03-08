import AgeKit

public class EncryptionManager {
    public static let shared = EncryptionManager()

    private let keyStore: KeyStore
    private var encryptionInterface: EncryptionInterface?

    public enum EncryptionBackend: String {
        case gpg
        case age

        public var fileExtension: String { rawValue }

        public static func isEncryptedFileExtension(_ ext: String) -> Bool {
            Self(rawValue: ext) != nil
        }
    }

    public init(keyStore: KeyStore = AppKeychain.shared) {
        self.keyStore = keyStore
    }

    public func initKeys() throws {
        let backend = Defaults.encryptionBackend
        switch backend {
        case .gpg:
            guard let publicKey: String = keyStore.get(for: PGPKey.PUBLIC.getKeychainKey()),
                  let privateKey: String = keyStore.get(for: PGPKey.PRIVATE.getKeychainKey()) else {
                encryptionInterface = nil
                throw AppError.keyImport
            }
            do {
                encryptionInterface = try GopenPGPInterface(publicArmoredKey: publicKey, privateArmoredKey: privateKey)
            } catch {
                encryptionInterface = nil // fallback is not supported anymore
                throw AppError.keyImport
            }
        case .age:
            guard let privateKeyString: String = keyStore.get(for: AgeKey.PRIVATE.getKeychainKey()) else {
                encryptionInterface = nil
                throw AppError.agePrivateKeyNotFound(keyID: "default")
            }
            do {
                let identity = try Age.parseIdentity(from: privateKeyString)
                encryptionInterface = Age(identity: identity)
            } catch {
                encryptionInterface = nil
                throw AppError.agePrivateKeyNotFound(keyID: "default")
            }
        }
    }

    public func uninitKeys() {
        encryptionInterface = nil
    }

    public func decrypt(encryptedData: Data, path: String, requestPassphrase: @escaping (String) -> String) throws -> Data? {
        try checkAndInit()
        guard let encryptionInterface else {
            throw AppError.decryption
        }

        if let gpgInterface = encryptionInterface as? PGPInterface {
            let keyID: String?
            if Defaults.isEnableGPGIDOn {
                keyID = gpgInterface.getRecipient(from: path)
            } else {
                keyID = gpgInterface.fallbackRecipient
            }

            if let keyID {
                if !gpgInterface.containsPrivateKey(with: keyID) {
                    throw AppError.pgpPrivateKeyNotFound(keyID: keyID)
                }
                let passphraseKey = AppKeychain.getPGPKeyPassphraseKey(keyID: keyID)
                if let storedPassphrase = keyStore.get(for: passphraseKey) {
                    do {
                        return try gpgInterface.decrypt(encryptedData: encryptedData, passphrase: storedPassphrase)
                    } catch AppError.wrongPassphrase {
                        keyStore.removeContent(for: passphraseKey)
                    }
                }
                let passphrase = requestPassphrase(keyID)
                return try gpgInterface.decrypt(encryptedData: encryptedData, passphrase: passphrase)
            }

            return try gpgInterface.decrypt(encryptedData: encryptedData, passphrase: "")
        }

        if encryptionInterface is Age {
            return try encryptionInterface.decrypt(encryptedData: encryptedData)
        }
        return nil
    }

    public func encrypt(plainData: Data, path: String) throws -> Data {
        try checkAndInit()
        guard let encryptionInterface else {
            throw AppError.encryption
        }

        let recipients: [String]
        if encryptionInterface is PGPInterface, !Defaults.isEnableGPGIDOn {
            guard let fallback = encryptionInterface.fallbackRecipient else {
                throw AppError.encryption
            }
            recipients = [fallback]
        } else {
            recipients = encryptionInterface.getRecipients(from: path)
        }

        guard !recipients.isEmpty else {
            throw AppError.encryption
        }

        if encryptionInterface is PGPInterface, recipients.count > 1 {
            throw AppError.gpgIDMultipleRecipients(count: recipients.count)
        }

        return try encryptionInterface.encrypt(plainData: plainData, recipients: recipients)
    }

    public var isPrepared: Bool {
        let backend = Defaults.encryptionBackend
        switch backend {
        case .gpg:
            return keyStore.contains(key: PGPKey.PUBLIC.getKeychainKey()) && keyStore.contains(key: PGPKey.PRIVATE.getKeychainKey())
        case .age:
            // Only check for private key - public key is derived
            return keyStore.contains(key: AgeKey.PRIVATE.getKeychainKey())
        }
    }

    private func checkAndInit() throws {
        if encryptionInterface == nil {
            try initKeys()
        }
    }
}
