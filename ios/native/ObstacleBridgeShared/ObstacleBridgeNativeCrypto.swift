import CommonCrypto
import CryptoKit
import Foundation

@objc(ObstacleBridgeNativeCrypto)
final class ObstacleBridgeNativeCrypto: NSObject {
    @objc class func availableFeatures() -> NSDictionary {
        return [
            "aesgcm": true,
            "chacha20poly1305": true,
            "hkdf_sha256": true,
            "pbkdf2_sha256": true,
            "ed25519": true,
            "x25519": true,
        ]
    }

    @objc class func hkdfSHA256Salt(
        _ salt: NSData,
        info: NSData,
        keyMaterial: NSData,
        length: NSNumber
    ) -> NSData? {
        let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        let outputLength = max(0, length.intValue)
        let saltData = (salt as Data).isEmpty ? Data(repeating: 0, count: digestLength) : (salt as Data)
        let infoData = info as Data
        let ikm = keyMaterial as Data
        let prk = hmacSHA256(key: saltData, message: ikm)
        var okm = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while okm.count < outputLength {
            var block = Data()
            block.append(previous)
            block.append(infoData)
            block.append(counter)
            previous = hmacSHA256(key: prk, message: block)
            okm.append(previous)
            counter = counter &+ 1
        }
        return okm.prefix(outputLength) as NSData
    }

    @objc class func pbkdf2SHA256Password(
        _ password: NSData,
        salt: NSData,
        iterations: NSNumber,
        length: NSNumber
    ) -> NSData? {
        let outputLength = max(0, length.intValue)
        var derived = Data(count: outputLength)
        let passwordData = password as Data
        let saltData = salt as Data
        let status = derived.withUnsafeMutableBytes { derivedBytes in
            saltData.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    String(decoding: passwordData, as: UTF8.self),
                    passwordData.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress,
                    saltData.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations.intValue),
                    derivedBytes.bindMemory(to: UInt8.self).baseAddress,
                    outputLength
                )
            }
        }
        guard status == kCCSuccess else {
            return nil
        }
        return derived as NSData
    }

    @objc class func aesGCMEncryptKey(
        _ key: NSData,
        nonce: NSData,
        plaintext: NSData,
        aad: NSData
    ) -> NSData? {
        do {
            let sealed = try AES.GCM.seal(
                plaintext as Data,
                using: SymmetricKey(data: key as Data),
                nonce: try AES.GCM.Nonce(data: nonce as Data),
                authenticating: aad as Data
            )
            return (sealed.ciphertext + sealed.tag) as NSData
        } catch {
            return nil
        }
    }

    @objc class func aesGCMDecryptKey(
        _ key: NSData,
        nonce: NSData,
        ciphertext: NSData,
        aad: NSData
    ) -> NSData? {
        do {
            let combined = (nonce as Data) + (ciphertext as Data)
            let sealed = try AES.GCM.SealedBox(combined: combined)
            let plaintext = try AES.GCM.open(
                sealed,
                using: SymmetricKey(data: key as Data),
                authenticating: aad as Data
            )
            return plaintext as NSData
        } catch {
            return nil
        }
    }

    @objc class func chaCha20Poly1305EncryptKey(
        _ key: NSData,
        nonce: NSData,
        plaintext: NSData,
        aad: NSData
    ) -> NSData? {
        do {
            let sealed = try ChaChaPoly.seal(
                plaintext as Data,
                using: SymmetricKey(data: key as Data),
                nonce: try ChaChaPoly.Nonce(data: nonce as Data),
                authenticating: aad as Data
            )
            return (sealed.ciphertext + sealed.tag) as NSData
        } catch {
            return nil
        }
    }

    @objc class func chaCha20Poly1305DecryptKey(
        _ key: NSData,
        nonce: NSData,
        ciphertext: NSData,
        aad: NSData
    ) -> NSData? {
        do {
            let combined = (nonce as Data) + (ciphertext as Data)
            let sealed = try ChaChaPoly.SealedBox(combined: combined)
            let plaintext = try ChaChaPoly.open(
                sealed,
                using: SymmetricKey(data: key as Data),
                authenticating: aad as Data
            )
            return plaintext as NSData
        } catch {
            return nil
        }
    }

    @objc class func generateEd25519PrivateKey() -> NSData {
        return Curve25519.Signing.PrivateKey().rawRepresentation as NSData
    }

    @objc class func ed25519PublicKeyFromPrivateRaw(_ privateKey: NSData) -> NSData? {
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey as Data)
            return key.publicKey.rawRepresentation as NSData
        } catch {
            return nil
        }
    }

    @objc class func ed25519SignPrivateKey(_ privateKey: NSData, message: NSData) -> NSData? {
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey as Data)
            return try key.signature(for: message as Data) as NSData
        } catch {
            return nil
        }
    }

    @objc class func ed25519VerifyPublicKey(
        _ publicKey: NSData,
        signature: NSData,
        message: NSData
    ) -> NSNumber {
        do {
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey as Data)
            return NSNumber(value: key.isValidSignature(signature as Data, for: message as Data))
        } catch {
            return NSNumber(value: false)
        }
    }

    @objc class func generateX25519PrivateKey() -> NSData {
        return Curve25519.KeyAgreement.PrivateKey().rawRepresentation as NSData
    }

    @objc class func x25519PublicKeyFromPrivateRaw(_ privateKey: NSData) -> NSData? {
        do {
            let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey as Data)
            return key.publicKey.rawRepresentation as NSData
        } catch {
            return nil
        }
    }

    @objc class func x25519SharedSecretPrivateKey(
        _ privateKey: NSData,
        peerPublicKey: NSData
    ) -> NSData? {
        do {
            let localKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey as Data)
            let remoteKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey as Data)
            let sharedSecret = try localKey.sharedSecretFromKeyAgreement(with: remoteKey)
            let data = sharedSecret.withUnsafeBytes { Data($0) }
            return data as NSData
        } catch {
            return nil
        }
    }

    private class func hmacSHA256(key: Data, message: Data) -> Data {
        let authenticationCode = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(authenticationCode)
    }
}
