import Foundation

/// Objective-C selector bridge for Apple host code. Cryptographic operations
/// are implemented only by `ObstacleBridgeCrypto` in the shared Core target.
@objc(ObstacleBridgeNativeCrypto)
final class ObstacleBridgeNativeCrypto: NSObject {
    @objc class func availableFeatures() -> NSDictionary {
        ["aesgcm": true, "chacha20poly1305": true, "hkdf_sha256": true,
         "pbkdf2_sha256": true, "ed25519": true, "x25519": true]
    }

    @objc class func hkdfSHA256Salt(_ salt: NSData, info: NSData, keyMaterial: NSData, length: NSNumber) -> NSData? {
        try? ObstacleBridgeCrypto.hkdfSHA256(
            salt: salt as Data, info: info as Data, keyMaterial: keyMaterial as Data,
            outputByteCount: max(0, length.intValue)
        ) as NSData
    }

    @objc class func hkdfSHA256Salt(_ salt: NSData, info: NSData, keyMaterial: NSData, lengthValue: Int) -> NSData? {
        hkdfSHA256Salt(salt, info: info, keyMaterial: keyMaterial, length: NSNumber(value: lengthValue))
    }

    @objc class func pbkdf2SHA256Password(_ password: NSData, salt: NSData, iterations: NSNumber, length: NSNumber) -> NSData? {
        try? ObstacleBridgeCrypto.pbkdf2SHA256(
            password: password as Data, salt: salt as Data, iterations: iterations.intValue,
            outputByteCount: max(0, length.intValue)
        ) as NSData
    }

    @objc class func pbkdf2SHA256Password(_ password: NSData, salt: NSData, iterationsValue: Int, lengthValue: Int) -> NSData? {
        pbkdf2SHA256Password(password, salt: salt, iterations: NSNumber(value: iterationsValue), length: NSNumber(value: lengthValue))
    }

    @objc class func aesGCMEncryptKey(_ key: NSData, nonce: NSData, plaintext: NSData, aad: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.aesGCMSeal(
            plaintext: plaintext as Data, key: key as Data, nonce: nonce as Data,
            authenticatedData: aad as Data
        ) as NSData
    }

    @objc class func aesGCMDecryptKey(_ key: NSData, nonce: NSData, ciphertext: NSData, aad: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.aesGCMOpen(
            ciphertextAndTag: ciphertext as Data, key: key as Data, nonce: nonce as Data,
            authenticatedData: aad as Data
        ) as NSData
    }

    @objc class func chaCha20Poly1305EncryptKey(_ key: NSData, nonce: NSData, plaintext: NSData, aad: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.chaChaPolySeal(
            plaintext: plaintext as Data, key: key as Data, nonce: nonce as Data,
            authenticatedData: aad as Data
        ) as NSData
    }

    @objc class func chaCha20Poly1305DecryptKey(_ key: NSData, nonce: NSData, ciphertext: NSData, aad: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.chaChaPolyOpen(
            ciphertextAndTag: ciphertext as Data, key: key as Data, nonce: nonce as Data,
            authenticatedData: aad as Data
        ) as NSData
    }

    @objc class func generateEd25519PrivateKey() -> NSData {
        ObstacleBridgeCrypto.generateEd25519PrivateKey() as NSData
    }

    @objc class func ed25519PublicKeyFromPrivateRaw(_ privateKey: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.ed25519PublicKey(privateKey: privateKey as Data) as NSData
    }

    @objc class func ed25519SignPrivateKey(_ privateKey: NSData, message: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.ed25519Sign(message: message as Data, privateKey: privateKey as Data) as NSData
    }

    @objc class func ed25519VerifyPublicKey(_ publicKey: NSData, signature: NSData, message: NSData) -> NSNumber {
        NSNumber(value: (try? ObstacleBridgeCrypto.ed25519Verify(signature: signature as Data, message: message as Data, publicKey: publicKey as Data)) ?? false)
    }

    @objc class func generateX25519PrivateKey() -> NSData {
        ObstacleBridgeCrypto.generateX25519PrivateKey() as NSData
    }

    @objc class func x25519PublicKeyFromPrivateRaw(_ privateKey: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.x25519PublicKey(privateKey: privateKey as Data) as NSData
    }

    @objc class func x25519SharedSecretPrivateKey(_ privateKey: NSData, peerPublicKey: NSData) -> NSData? {
        try? ObstacleBridgeCrypto.x25519SharedSecret(privateKey: privateKey as Data, peerPublicKey: peerPublicKey as Data) as NSData
    }
}
