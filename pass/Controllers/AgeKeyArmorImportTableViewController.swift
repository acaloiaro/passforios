//
//  AgeKeyArmorImportTableViewController.swift
//  pass
//
//  Created by Mingshen Sun on 17/2/2017.
//  Copyright © 2017 Bob Sun. All rights reserved.
//

import AgeKit
import passKit
import UIKit

class AgeKeyArmorImportTableViewController: AutoCellHeightUITableViewController, UITextViewDelegate {
    @IBOutlet var armorPublicKeyTextView: UITextView!
    @IBOutlet var armorPrivateKeyTextView: UITextView!

    private var armorPublicKey: String?
    private var armorPrivateKey: String?

    override func viewDidLoad() {
        super.viewDidLoad()
        // Pre-populate with existing keys from Keychain
        if let existingPublicKey = AppKeychain.shared.get(for: AgeKey.PUBLIC.getKeychainKey()) {
            armorPublicKeyTextView.text = existingPublicKey
        }
        if let existingPrivateKey = AppKeychain.shared.get(for: AgeKey.PRIVATE.getKeychainKey()) {
            armorPrivateKeyTextView.text = existingPrivateKey
        }
    }

    @IBAction
    private func save(_: Any) {
        armorPublicKey = armorPublicKeyTextView.text
        armorPrivateKey = armorPrivateKeyTextView.text
        saveImportedKeys()
    }

    func textView(_: UITextView, shouldChangeTextIn _: NSRange, replacementText text: String) -> Bool {
        if text == UIPasteboard.general.string {
            // user pastes something, do the copy here again and clear the pasteboard in 45s
            SecurePasteboard.shared.copy(textToCopy: text)
        }
        return true
    }
}

extension AgeKeyArmorImportTableViewController: AgeKeyImporter {
    static let keySource = KeySource.ageArmor
    static let label = "AsciiArmorAgeKey".localize()

    func isReadyToUse() -> Bool {
        let publicKey = armorPublicKeyTextView.text.trimmingCharacters(in: .whitespacesAndNewlines)
        let privateKey = armorPrivateKeyTextView.text.trimmingCharacters(in: .whitespacesAndNewlines)

        // Check if keys are not empty
        guard !publicKey.isEmpty else {
            Utils.alert(title: "CannotSave".localize(), message: "SetAgePublicKey.".localize(), controller: self, completion: nil)
            return false
        }
        guard !privateKey.isEmpty else {
            Utils.alert(title: "CannotSave".localize(), message: "SetAgePrivateKey.".localize(), controller: self, completion: nil)
            return false
        }

        // Validate public key format (should start with "age1")
        guard publicKey.hasPrefix("age1") else {
            Utils.alert(
                title: "CannotSave".localize(),
                message: "Age public key must start with 'age1'. Please check the key format.",
                controller: self,
                completion: nil
            )
            return false
        }

        // Validate private key format (should start with "AGE-SECRET-KEY-1")
        guard privateKey.hasPrefix("AGE-SECRET-KEY-1") else {
            Utils.alert(
                title: "CannotSave".localize(),
                message: "Age private key must start with 'AGE-SECRET-KEY-1'. Please check the key format.",
                controller: self,
                completion: nil
            )
            return false
        }

        // Validate that keys can be parsed by AgeKit
        do {
            _ = try AgeKit.Age.X25519Recipient(publicKey)
        } catch {
            Utils.alert(
                title: "CannotSave".localize(),
                message: "Invalid Age public key format: \(error.localizedDescription)",
                controller: self,
                completion: nil
            )
            return false
        }

        do {
            // Parse identity from private key string
            guard let keyData = privateKey.data(using: .utf8) else {
                Utils.alert(
                    title: "CannotSave".localize(),
                    message: "Invalid Age private key encoding",
                    controller: self,
                    completion: nil
                )
                return false
            }
            let inputStream = InputStream(data: keyData)
            inputStream.open()
            defer { inputStream.close() }

            let identities = try AgeKit.Age.parseIdentities(input: inputStream)
            guard identities.first is AgeKit.Age.X25519Identity else {
                Utils.alert(
                    title: "CannotSave".localize(),
                    message: "No valid X25519 identity found in private key",
                    controller: self,
                    completion: nil
                )
                return false
            }
        } catch {
            Utils.alert(
                title: "CannotSave".localize(),
                message: "Invalid Age private key format: \(error.localizedDescription)",
                controller: self,
                completion: nil
            )
            return false
        }

        return true
    }

    func importKeys() throws {
        try KeyFileManager.PublicAge.importKey(from: armorPublicKey ?? "")
        try KeyFileManager.PrivateAge.importKey(from: armorPrivateKey ?? "")
    }

    func saveImportedKeys() {
        performSegue(withIdentifier: "saveAgeKeySegue", sender: self)
    }
}
