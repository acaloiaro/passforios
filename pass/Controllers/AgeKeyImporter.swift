//
//  AgeKeyImporter.swift
//  pass
//
//  Created by Mingshen Sun on 17/2/2017.
//  Copyright © 2017 Bob Sun. All rights reserved.
//

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
