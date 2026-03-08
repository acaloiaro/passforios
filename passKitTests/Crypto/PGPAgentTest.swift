//
//  PGPAgentTest.swift
//  passKitTests
//
//  Created by Yishi Lin on 2019/7/17.
//  Copyright © 2019 Bob Sun. All rights reserved.
//

import SwiftyUserDefaults
import XCTest

@testable import passKit

final class PGPAgentTest: XCTestCase {
    private var keychain: KeyStore!
    private var pgpAgent: PGPAgent!
    private var encryptionManager: EncryptionManager!

    private let testData = Data("Hello World!".utf8)

    override func setUp() {
        super.setUp()
        keychain = DictBasedKeychain()
        pgpAgent = PGPAgent(keyStore: keychain)
        encryptionManager = EncryptionManager(keyStore: keychain)
        UserDefaults().removePersistentDomain(forName: "SharedDefaultsForPGPAgentTest")
        passKit.Defaults = DefaultsAdapter(defaults: UserDefaults(suiteName: "SharedDefaultsForPGPAgentTest")!, keyStore: DefaultsKeys())
    }

    override func tearDown() {
        keychain.removeAllContent()
        encryptionManager.uninitKeys()
        UserDefaults().removePersistentDomain(forName: "SharedDefaultsForPGPAgentTest")
        super.tearDown()
    }

    private func makeInterface(publicKey: String, privateKey: String) throws -> PGPInterface {
        try GopenPGPInterface(publicArmoredKey: publicKey, privateArmoredKey: privateKey)
    }

    private func basicEncryptDecrypt(using pgpInterface: PGPInterface, keyID: String, encryptKeyID: String? = nil, passphrase: String = "passforios", encryptInArmored: Bool = true, decryptFromArmored: Bool = true) throws -> Data? {
        passKit.Defaults.encryptInArmored = encryptInArmored
        let encryptedData = try pgpInterface.encrypt(plainData: testData, keyID: keyID)
        passKit.Defaults.encryptInArmored = decryptFromArmored
        return try pgpInterface.decrypt(encryptedData: encryptedData, keyID: encryptKeyID ?? keyID, passphrase: passphrase)
    }

    func testMultiKeys() throws {
        try [
            RSA2048_RSA4096,
            ED25519_NISTP384,
        ].forEach { testKeyInfo in
            keychain.removeAllContent()
            try importKeys(testKeyInfo.publicKeys, testKeyInfo.privateKeys)
            XCTAssert(pgpAgent.isPrepared)
            let pgpInterface = try GopenPGPInterface(publicArmoredKey: testKeyInfo.publicKeys, privateArmoredKey: testKeyInfo.privateKeys)
            for id in testKeyInfo.fingerprints {
                XCTAssert(pgpInterface.containsPublicKey(with: id))
                XCTAssert(pgpInterface.containsPrivateKey(with: id))
            }
        }
        // Verify each key pair encrypts and decrypts correctly
        for testSet in [RSA2048, RSA4096, ED25519, NISTP384] as [PGPTestSet] {
            let pgpInterface = try makeInterface(publicKey: testSet.publicKey, privateKey: testSet.privateKey)
            try [
                (true, true),
                (true, false),
                (false, true),
                (false, false),
            ].forEach { encryptInArmored, decryptFromArmored in
                XCTAssertEqual(try basicEncryptDecrypt(using: pgpInterface, keyID: testSet.fingerprint, passphrase: testSet.passphrase, encryptInArmored: encryptInArmored, decryptFromArmored: decryptFromArmored), testData)
            }
        }
    }

    func testBasicEncryptDecrypt() throws {
        try [
            RSA2048,
            RSA2048_SUB,
            RSA3072_NO_PASSPHRASE,
            RSA4096,
            RSA4096_SUB,
            ED25519,
            ED25519_SUB,
            NISTP384,
        ].forEach { testKeyInfo in
            keychain.removeAllContent()
            try importKeys(testKeyInfo.publicKey, testKeyInfo.privateKey)
            XCTAssert(pgpAgent.isPrepared)
            let pgpInterface = try makeInterface(publicKey: testKeyInfo.publicKey, privateKey: testKeyInfo.privateKey)
            XCTAssert(pgpInterface.keyID.first!.lowercased().hasSuffix(testKeyInfo.fingerprint))
            try [
                (true, true),
                (true, false),
                (false, true),
                (false, false),
            ].forEach { encryptInArmored, decryptFromArmored in
                XCTAssertEqual(try basicEncryptDecrypt(using: pgpInterface, keyID: testKeyInfo.fingerprint, passphrase: testKeyInfo.passphrase, encryptInArmored: encryptInArmored, decryptFromArmored: decryptFromArmored), testData)
            }
        }
    }

    func testNoPrivateKey() throws {
        try KeyFileManager(keyType: PGPKey.PUBLIC, keyPath: "", keyHandler: keychain.add).importKey(from: RSA2048.publicKey)
        XCTAssertFalse(pgpAgent.isPrepared)
        XCTAssertThrowsError(try encryptionManager.initKeys()) {
            XCTAssertEqual($0 as! AppError, AppError.keyImport)
        }
        XCTAssertThrowsError(try encryptionManager.encrypt(plainData: testData, path: "test.gpg")) {
            XCTAssertEqual($0 as! AppError, AppError.keyImport)
        }
    }

    func testInterchangePublicAndPrivateKey() throws {
        try importKeys(RSA2048.privateKey, RSA2048.publicKey)
        XCTAssert(pgpAgent.isPrepared)
        XCTAssertThrowsError(try basicEncryptDecrypt(using: makeInterface(publicKey: RSA2048.privateKey, privateKey: RSA2048.publicKey), keyID: RSA2048.fingerprint)) {
            XCTAssert($0.localizedDescription.contains("gopenpgp: unable to add locked key to a keyring"))
        }
    }

    func testIncompatibleKeyTypes() throws {
        try importKeys(ED25519.publicKey, RSA2048.privateKey)
        XCTAssert(pgpAgent.isPrepared)
        let pgpInterface = try makeInterface(publicKey: ED25519.publicKey, privateKey: RSA2048.privateKey)
        XCTAssertThrowsError(try basicEncryptDecrypt(using: pgpInterface, keyID: ED25519.fingerprint, encryptKeyID: RSA2048.fingerprint)) {
            XCTAssertEqual($0 as! AppError, AppError.keyExpiredOrIncompatible)
        }
    }

    func testCorruptedKey() throws {
        try importKeys(RSA2048.publicKey.replacingOccurrences(of: "1", with: ""), RSA2048.privateKey)
        XCTAssert(pgpAgent.isPrepared)
        XCTAssertThrowsError(try encryptionManager.initKeys()) {
            XCTAssertEqual($0 as! AppError, AppError.keyImport)
        }
    }

    func testUnsetKeys() throws {
        try importKeys(ED25519.publicKey, ED25519.privateKey)
        XCTAssert(pgpAgent.isPrepared)
        let pgpInterface = try makeInterface(publicKey: ED25519.publicKey, privateKey: ED25519.privateKey)
        XCTAssertEqual(try basicEncryptDecrypt(using: pgpInterface, keyID: ED25519.fingerprint, passphrase: ED25519.passphrase), testData)
        keychain.removeContent(for: PGPKey.PUBLIC.getKeychainKey())
        keychain.removeContent(for: PGPKey.PRIVATE.getKeychainKey())
        XCTAssertFalse(pgpAgent.isPrepared)
        encryptionManager.uninitKeys()
        XCTAssertThrowsError(try encryptionManager.encrypt(plainData: testData, path: "test.gpg")) {
            XCTAssertEqual($0 as! AppError, AppError.keyImport)
        }
    }

    func testNoDecryptionWithIncorrectPassphrase() throws {
        try importKeys(RSA2048.publicKey, RSA2048.privateKey)
        let pgpInterface = try makeInterface(publicKey: RSA2048.publicKey, privateKey: RSA2048.privateKey)

        // Provide the correct passphrase.
        XCTAssertEqual(try basicEncryptDecrypt(using: pgpInterface, keyID: RSA2048.fingerprint, passphrase: RSA2048.passphrase), testData)

        // Provide the wrong passphrase.
        XCTAssertThrowsError(try basicEncryptDecrypt(using: pgpInterface, keyID: RSA2048.fingerprint, passphrase: "incorrect passphrase")) {
            XCTAssertEqual($0 as! AppError, AppError.wrongPassphrase)
        }

        // Provide the correct passphrase again.
        XCTAssertEqual(try basicEncryptDecrypt(using: pgpInterface, keyID: RSA2048.fingerprint, passphrase: RSA2048.passphrase), testData)
    }

    private func importKeys(_ publicKey: String, _ privateKey: String) throws {
        try KeyFileManager(keyType: PGPKey.PUBLIC, keyPath: "", keyHandler: keychain.add).importKey(from: publicKey)
        try KeyFileManager(keyType: PGPKey.PRIVATE, keyPath: "", keyHandler: keychain.add).importKey(from: privateKey)
    }
}
