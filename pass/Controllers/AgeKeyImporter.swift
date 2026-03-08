import passKit

protocol AgeKeyImporter: KeyImporter {
    func doAfterImport()
}

extension AgeKeyImporter {
    static var isCurrentKeySource: Bool {
        Defaults.ageKeySource == keySource
    }

    func doAfterImport() {}
}
