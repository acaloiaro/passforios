//
//  AgeTest.swift
//  passKitTests
//
//  Created on 2026/3/14.
//

import AgeKit
import XCTest

@testable import passKit

private typealias AgeInterface = passKit.Age

final class AgeTest: XCTestCase {
    private let testData = Data("Hello World!".utf8)
    private var identity: AgeKit.Age.X25519Identity!
    private var age: AgeInterface!

    override func setUp() {
        super.setUp()
        identity = AgeKit.Age.X25519Identity.generate()
        age = AgeInterface(identity: identity)
    }

    // MARK: - parseIdentity / derivePublicKey

    func testParseIdentityFromPrivateKeyString() throws {
        let parsed = try AgeInterface.parseIdentity(from: identity.string)
        XCTAssertEqual(parsed.recipient.string, identity.recipient.string)
    }

    func testParseIdentityWithInvalidStringThrows() {
        XCTAssertThrowsError(try AgeInterface.parseIdentity(from: "not-a-valid-key"))
    }

    func testDerivePublicKeyMatchesIdentityRecipient() throws {
        let publicKey = try AgeInterface.derivePublicKey(from: identity.string)
        XCTAssertEqual(publicKey, identity.recipient.string)
        XCTAssert(publicKey.hasPrefix(AgeInterface.publicKeyPrefix))
    }

    // MARK: - getPublicKey / containsRecipient / fallbackRecipient

    func testGetPublicKeyMatchesDerivedKey() throws {
        let derived = try AgeInterface.derivePublicKey(from: identity.string)
        XCTAssertEqual(age.getPublicKey(), derived)
    }

    func testContainsRecipientMatchesOwnKey() {
        XCTAssert(age.containsRecipient(age.getPublicKey()))
    }

    func testContainsRecipientRejectsOtherKey() {
        let other = AgeKit.Age.X25519Identity.generate()
        XCTAssertFalse(age.containsRecipient(other.recipient.string))
    }

    func testFallbackRecipientEqualsPublicKey() {
        XCTAssertEqual(age.fallbackRecipient, age.getPublicKey())
    }

    // MARK: - Encrypt / Decrypt round-trip

    func testEncryptDecryptRoundTrip() throws {
        let encrypted = try age.encrypt(plainData: testData, recipient: age.getPublicKey())
        let decrypted = try age.decrypt(encryptedData: encrypted)
        XCTAssertEqual(decrypted, testData)
    }

    func testMultiRecipientEncryptDecrypt() throws {
        let identity2 = AgeKit.Age.X25519Identity.generate()
        let age2 = AgeInterface(identity: identity2)

        let recipients = [age.getPublicKey(), age2.getPublicKey()]
        let encrypted = try age.encrypt(plainData: testData, recipients: recipients)

        XCTAssertEqual(try age.decrypt(encryptedData: encrypted), testData)
        XCTAssertEqual(try age2.decrypt(encryptedData: encrypted), testData)
    }

    // MARK: - Decrypt errors

    func testDecryptWithWrongKeyThrowsKeyMismatch() throws {
        let other = AgeInterface(identity: AgeKit.Age.X25519Identity.generate())
        let encrypted = try age.encrypt(plainData: testData, recipient: age.getPublicKey())

        XCTAssertThrowsError(try other.decrypt(encryptedData: encrypted)) {
            XCTAssertEqual($0 as? AppError, AppError.decryptionKeyMismatch)
        }
    }

    func testDecryptGarbageDataThrows() {
        let garbage = Data("this is not age ciphertext".utf8)
        XCTAssertThrowsError(try age.decrypt(encryptedData: garbage))
    }

    // MARK: - Encrypt errors

    func testEncryptWithEmptyRecipientsThrows() {
        XCTAssertThrowsError(try age.encrypt(plainData: testData, recipients: [])) {
            XCTAssertEqual($0 as? AppError, AppError.encryption)
        }
    }

    func testEncryptWithInvalidRecipientThrows() {
        XCTAssertThrowsError(try age.encrypt(plainData: testData, recipient: "not-a-valid-recipient")) {
            XCTAssertEqual($0 as? AppError, AppError.agePublicKeyNotFound(keyID: "not-a-valid-recipient"))
        }
    }
}
