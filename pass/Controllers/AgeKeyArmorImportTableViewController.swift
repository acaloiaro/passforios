import AgeKit
import passKit
import UIKit

class AgeKeyArmorImportTableViewController: AutoCellHeightUITableViewController, UITextViewDelegate {
    @IBOutlet var armorPrivateKeyTextView: UITextView!
    @IBOutlet var publicKeyLabel: UILabel!
    @IBOutlet var copyPublicKeyButton: UIButton!

    private var armorPrivateKey: String?

    override func viewDidLoad() {
        super.viewDidLoad()
        armorPrivateKeyTextView.delegate = self
        copyPublicKeyButton.setImage(UIImage(systemName: "doc.on.doc"), for: .normal)
        copyPublicKeyButton.isEnabled = false

        // Pre-populate with existing private key from Keychain
        if let existingPrivateKey = AppKeychain.shared.get(for: AgeKey.PRIVATE.getKeychainKey()) {
            armorPrivateKeyTextView.text = existingPrivateKey
            updatePublicKey(from: existingPrivateKey)
        } else {
            publicKeyLabel.text = "PublicKeyAutomatic.".localize()
        }
    }

    private func updatePublicKey(from privateKeyText: String?) {
        guard let privateKeyText = privateKeyText?.trimmed, !privateKeyText.isEmpty else {
            publicKeyLabel.text = "PublicKeyAutomatic.".localize()
            copyPublicKeyButton.isEnabled = false
            return
        }

        do {
            let publicKey = try Age.derivePublicKey(from: privateKeyText)
            publicKeyLabel.text = publicKey
            copyPublicKeyButton.isEnabled = true
        } catch {
            publicKeyLabel.text = "PublicKeyAutomatic.".localize()
            copyPublicKeyButton.isEnabled = false
        }
    }

    @IBAction
    private func copyPublicKey(_: Any) {
        guard copyPublicKeyButton.isEnabled, let publicKey = publicKeyLabel.text else {
            return
        }

        SecurePasteboard.shared.copy(textToCopy: publicKey, expirationTime: 0)

        let alert = UIAlertController(
            title: nil,
            message: "PublicKeyCopied.".localize(),
            preferredStyle: .alert
        )
        present(alert, animated: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            alert.dismiss(animated: true)
        }
    }

    @IBAction
    private func save(_: Any) {
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

    func textViewDidChange(_ textView: UITextView) {
        updatePublicKey(from: textView.text)
    }
}

extension AgeKeyArmorImportTableViewController: AgeKeyImporter {
    static let keySource = KeySource.ageArmor
    static let label = "AsciiArmorAgeKey".localize()

    func isReadyToUse() -> Bool {
        let privateKey = armorPrivateKeyTextView.text.trimmed

        // Check if private key is not empty
        guard !privateKey.isEmpty else {
            Utils.alert(title: "CannotSave".localize(), message: "SetAgePrivateKey.".localize(), controller: self, completion: nil)
            return false
        }

        // Validate private key format
        guard privateKey.hasPrefix(Age.privateKeyPrefix) else {
            Utils.alert(
                title: "CannotSave".localize(),
                message: String(format: "AgeKeyInvalidPrefix.".localize(), Age.privateKeyPrefix),
                controller: self,
                completion: nil
            )
            return false
        }

        // Validate that private key can be parsed and public key can be derived
        do {
            _ = try Age.derivePublicKey(from: privateKey)
        } catch {
            Utils.alert(
                title: "CannotSave".localize(),
                message: String(format: "AgeKeyInvalidFormat.".localize(), error.localizedDescription),
                controller: self,
                completion: nil
            )
            return false
        }

        return true
    }

    func importKeys() throws {
        // Only import private key - public key is derived
        try KeyFileManager.PrivateAge.importKey(from: armorPrivateKey ?? "")
    }

    func saveImportedKeys() {
        performSegue(withIdentifier: "saveAgeKeySegue", sender: self)
    }
}
