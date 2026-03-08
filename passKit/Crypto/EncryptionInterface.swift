//
//  EncryptionInterface.swift
//  passKit
//
//  Created by Danny Moesch on 08.09.19.
//  Copyright © 2019 Bob Sun. All rights reserved.
//

protocol EncryptionInterface {
    func decrypt(encryptedData: Data) throws -> Data?

    func encrypt(plainData: Data, recipient: String) throws -> Data

    func getRecipient(from path: String) -> String?
}
