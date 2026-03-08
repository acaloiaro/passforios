protocol EncryptionInterface {
    func decrypt(encryptedData: Data) throws -> Data?

    func encrypt(plainData: Data, recipient: String) throws -> Data

    func getRecipient(from path: String) -> String?
}
