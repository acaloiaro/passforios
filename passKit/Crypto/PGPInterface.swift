protocol PGPInterface: EncryptionInterface {
    func decrypt(encryptedData: Data, keyID: String?, passphrase: String) throws -> Data?

    func decrypt(encryptedData: Data, passphrase: String) throws -> Data?

    func encrypt(plainData: Data, keyID: String?) throws -> Data

    func containsPublicKey(with keyID: String) -> Bool

    func containsPrivateKey(with keyID: String) -> Bool

    var keyID: [String] { get }

    var shortKeyID: [String] { get }
}
