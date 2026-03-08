//
//  PasswordStoreTest.swift
//  passKitTests
//
//  Created by Mingshen Sun on 13/4/2020.
//  Copyright © 2020 Bob Sun. All rights reserved.
//

import Foundation
import ObjectiveGit
import XCTest

@testable import passKit

final class PasswordStoreTest: XCTestCase {
    private let remoteRepoURL = URL(string: "https://github.com/mssun/passforios-password-store.git")!

    func testCloneAndDecryptMultiKeys() throws {
        let url = Globals.sharedContainerURL.appendingPathComponent("Library/password-store-test/")

        Defaults.isEnableGPGIDOn = true
        let passwordStore = PasswordStore(url: url)
        try passwordStore.cloneRepository(remoteRepoURL: remoteRepoURL, branchName: "master")
        expectation(for: NSPredicate { _, _ in FileManager.default.fileExists(atPath: url.path) }, evaluatedWith: nil)
        waitForExpectations(timeout: 3, handler: nil)

        let keychain = AppKeychain.shared
        try KeyFileManager(keyType: PGPKey.PUBLIC, keyPath: "", keyHandler: keychain.add).importKey(from: RSA2048_RSA4096.publicKeys)
        try KeyFileManager(keyType: PGPKey.PRIVATE, keyPath: "", keyHandler: keychain.add).importKey(from: RSA2048_RSA4096.privateKeys)
        try EncryptionManager.shared.initKeys()

        let personal = try decrypt(passwordStore: passwordStore, path: "personal/github.com.gpg")
        XCTAssertEqual(personal.plainText, "passwordforpersonal\n")

        let work = try decrypt(passwordStore: passwordStore, path: "work/github.com.gpg")
        XCTAssertEqual(work.plainText, "passwordforwork\n")

        let testPassword = Password(name: "test", path: "test.gpg", plainText: "testpassword")
        let testPasswordEntity = try passwordStore.add(password: testPassword, path: "test.gpg")!
        let testPasswordPlain = try passwordStore.decrypt(passwordEntity: testPasswordEntity, requestPassphrase: requestPGPKeyPassphrase)
        XCTAssertEqual(testPasswordPlain.plainText, "testpassword")

        passwordStore.erase()
        Defaults.isEnableGPGIDOn = false
    }

    private func decrypt(passwordStore: PasswordStore, path: String) throws -> Password {
        let entity = passwordStore.fetchPasswordEntity(with: path)!
        return try passwordStore.decrypt(passwordEntity: entity, requestPassphrase: requestPGPKeyPassphrase)
    }
}
