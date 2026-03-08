//
//  GPGInterface.swift
//  passKit
//
//  Created by Danny Moesch on 28.12.25.
//  Copyright © 2025 Bob Sun. All rights reserved.
//

protocol GPGInterface: EncryptionInterface {
    func containsPublicKey(with keyID: String) -> Bool

    func containsPrivateKey(with keyID: String) -> Bool

    func decrypt(encryptedData: Data, passphrase: String) throws -> Data?

    var keyID: [String] { get }

    var shortKeyID: [String] { get }
}
