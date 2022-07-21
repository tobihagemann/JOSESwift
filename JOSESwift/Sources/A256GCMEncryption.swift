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
    /*
     See: https://tools.ietf.org/html/rfc7516 -
     3.3.  Example JWE
     A.1.  Example JWE using RSAES-OAEP and AES GCM
     */
    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        /*
         
         Assemble the final representation: The Compact Serialization of this
         result is the string BASE64URL(UTF8(JWE Protected Header)) || '.' ||
         BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization
         Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE
         Authentication Tag).
         
         */
        //key is in RSA-OAEP (elsewhere)
       
        let iv =  Data(bytes: [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219] as [UInt8], count: 12)
        let nonce: Data = Data() // todo what where?
        let plaintext: Data = "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)!
        /*
          Let the Additional Authenticated Data encryption parameter be
          ASCII(BASE64URL(UTF8(JWE Protected Header))).  This value is:
        */
        

        let tagSize = SwiftGCM.tagSize128
        let gcmEnc: SwiftGCM = try SwiftGCM(key: contentEncryptionKey, nonce: iv, tagSize: SwiftGCM.tagSize128)  // inferred from example length = SwiftGCM.tagSize128
        let ciphertextAndTag: Data = try gcmEnc.encrypt(auth: additionalAuthenticatedData, plaintext: plaintext)
        let authenticationTag = ciphertextAndTag.suffix(tagSize) // extract the last [tagsize] bytes
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - authenticationTag.count) // extract everything before the [tagsize] bytes

        return ContentEncryptionContext(
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }

    func decrypt(
        _ ciphertext: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        return Data()
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
