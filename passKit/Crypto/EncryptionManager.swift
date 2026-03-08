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

        if let gpgInterface = encryptionInterface as? PGPInterface, let keyID = gpgInterface.getRecipient(from: path) {
            if !gpgInterface.containsPrivateKey(with: keyID) {
                throw AppError.pgpPrivateKeyNotFound(keyID: keyID)
            }

            let passphrase = keyStore.get(for: AppKeychain.getPGPKeyPassphraseKey(keyID: keyID)) ?? requestPassphrase(keyID)
            guard let result = try gpgInterface.decrypt(encryptedData: encryptedData, passphrase: passphrase) else {
                return nil
            }
            return result
        }
        if encryptionInterface is Age {
            // Age decryption doesn't require a passphrase for the private key to decrypt,
            // as the private key is already loaded from the Keychain (if found).
            // Any passphrase handling for AgeKit would happen during key generation/import
            // and storage, not during decryption.
            return try encryptionInterface.decrypt(encryptedData: encryptedData)
        }
        return nil
    }

    public func encrypt(plainData: Data, path: String) throws -> Data {
        try checkAndInit()
        guard let encryptionInterface else {
            throw AppError.encryption
        }
        guard let recipient = encryptionInterface.getRecipient(from: path) else {
            throw AppError.encryption
        }
        return try encryptionInterface.encrypt(plainData: plainData, recipient: recipient)
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
