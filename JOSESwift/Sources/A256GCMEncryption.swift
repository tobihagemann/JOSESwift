//
//  A256GCMEncryption.swift
//  JOSESwift
//
//  Created by Mitchell Currie on 20/5/20.
//

import Foundation
import CryptoKit

struct A256GCMEncryption {
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let contentEncryptionKey: Data

    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: Data) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.contentEncryptionKey = contentEncryptionKey
    }

    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        let key = CryptoKit.SymmetricKey(data: contentEncryptionKey)
        let nonce = CryptoKit.AES.GCM.Nonce()
        let encrypted = try CryptoKit.AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: additionalAuthenticatedData)
        return ContentEncryptionContext(
            ciphertext: encrypted.ciphertext,
            authenticationTag: encrypted.tag,
            initializationVector: encrypted.nonce.withUnsafeBytes({ Data(Array($0)) })
        )
    }

    func decrypt(
        _ ciphertext: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        let key = CryptoKit.SymmetricKey(data: contentEncryptionKey)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)
        let encrypted = try CryptoKit.AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: authenticationTag)
        let decrypted = try CryptoKit.AES.GCM.open(encrypted, using: key, authenticating: additionalAuthenticatedData)
        return decrypted
    }
}

extension A256GCMEncryption: ContentEncrypter {
    func encrypt(headerData: Data, payload: Payload) throws -> ContentEncryptionContext {
        let plaintext = payload.data()
        let additionalAuthenticatedData = headerData.base64URLEncodedData()

        return try encrypt(plaintext, additionalAuthenticatedData: additionalAuthenticatedData)
    }
}

extension A256GCMEncryption: ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag
        )
    }
}
