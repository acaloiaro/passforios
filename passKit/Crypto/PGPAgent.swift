//
//  PGPAgent.swift
//  passKit
//
//  Created by Yishi Lin on 2019/7/17.
//  Copyright © 2019 Bob Sun. All rights reserved.
//

public class PGPAgent {
    public static let shared = PGPAgent()

    private let keyStore: KeyStore

    public init(keyStore: KeyStore = AppKeychain.shared) {
        self.keyStore = keyStore
    }

    public func getKeyID() throws -> [String] {
        guard let publicKey: String = keyStore.get(for: PGPKey.PUBLIC.getKeychainKey()),
              let privateKey: String = keyStore.get(for: PGPKey.PRIVATE.getKeychainKey()) else {
            return []
        }
        var pgpInterface: PGPInterface?
        do {
            pgpInterface = try GopenPGPInterface(publicArmoredKey: publicKey, privateArmoredKey: privateKey)
        } catch {
            pgpInterface = try ObjectivePGPInterface(publicArmoredKey: publicKey, privateArmoredKey: privateKey)
        }
        return pgpInterface?.keyID ?? []
    }

    public func getShortKeyID() throws -> [String] {
        guard let publicKey: String = keyStore.get(for: PGPKey.PUBLIC.getKeychainKey()),
              let privateKey: String = keyStore.get(for: PGPKey.PRIVATE.getKeychainKey()) else {
            return []
        }
        var pgpInterface: PGPInterface?
        do {
            pgpInterface = try GopenPGPInterface(publicArmoredKey: publicKey, privateArmoredKey: privateKey)
        } catch {
            pgpInterface = try ObjectivePGPInterface(publicArmoredKey: publicKey, privateArmoredKey: privateKey)
        }
        return pgpInterface?.shortKeyID.sorted() ?? []
    }

    public var isPrepared: Bool {
        keyStore.contains(key: PGPKey.PUBLIC.getKeychainKey())
            && keyStore.contains(key: PGPKey.PRIVATE.getKeychainKey())
    }
}
