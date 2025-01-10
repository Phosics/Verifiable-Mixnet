package org.example

import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint
import com.google.protobuf.ByteString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import org.example.crypto.ElGamal
import org.example.crypto.KeySerialization
import java.security.Security
import java.util.Scanner

/**
 * Main demonstrates the usage of EC-ElGamal encryption, rerandomization, and decryption.
 */
fun main() {
    try {
        // Add Bouncy Castle as a Security Provider
        Security.addProvider(BouncyCastleProvider())

        // Initialize cryptographic configuration
        val keyPair = CryptoConfig.generateKeyPair()
        val publicKey = CryptoConfig.getPublicKey(keyPair)
        val privateKey = CryptoConfig.getPrivateKey(keyPair)
        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters

        // Serialize the public key into ElGamalPublicKey Protobuf message
        val elGamalPublicKey = KeySerialization.createElGamalPublicKey(publicKey)
        println("ElGamal Public Key (DER): ${elGamalPublicKey.subjectPublicKeyInfo.toHex()}")

        // Prompt user for input message
        val scanner = Scanner(System.`in`)
        print("Enter the message to encrypt: ")
        val userInput = scanner.nextLine()

        // Encrypt the message
        val encryptedMessage: RerandomizableEncryptedMessage = ElGamal.encrypt(publicKey, userInput, domainParameters)
        println("Encrypted Message: ${encryptedMessage.data.toHex()}")

        // Rerandomize the ciphertext twice
        val firstRerandomizedCiphertext = ElGamal.rerandomizeCiphertext(
            CryptoUtils.unwrapCiphertext(encryptedMessage),
            publicKey,
            domainParameters
        )
        val firstRerandomizedMessage = CryptoUtils.wrapCiphertext(firstRerandomizedCiphertext)
        println("First Rerandomized Encrypted Message: ${firstRerandomizedMessage.data.toHex()}")

        val secondRerandomizedCiphertext = ElGamal.rerandomizeCiphertext(
            CryptoUtils.unwrapCiphertext(firstRerandomizedMessage),
            publicKey,
            domainParameters
        )
        val secondRerandomizedMessage = CryptoUtils.wrapCiphertext(secondRerandomizedCiphertext)
        println("Second Rerandomized Encrypted Message: ${secondRerandomizedMessage.data.toHex()}")

        // Decrypt the final ciphertext
        val decryptedMessage: String = ElGamal.decrypt(privateKey, secondRerandomizedMessage, domainParameters)
        println("Decrypted Message: $decryptedMessage")

        // Verify that the decrypted message matches the original message
        if (userInput == decryptedMessage) {
            println("Success: Decrypted message matches the original message.")
        } else {
            println("Error: Decrypted message does not match the original message.")
        }
    } catch (e: IllegalArgumentException) {
        println("Encryption/Decryption Error: ${e.message}")
    } catch (e: Exception) {
        println("An unexpected error occurred: ${e.message}")
    }
}

/**
 * Extension function to convert ByteString to hex string.
 */
fun ByteString.toHex(): String {
    return org.bouncycastle.util.encoders.Hex.toHexString(this.toByteArray())
}
