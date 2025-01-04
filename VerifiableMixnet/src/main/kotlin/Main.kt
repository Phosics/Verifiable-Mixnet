package org.example

import mixnet.MixServer
import mixnet.MixServersManager
import mixnet.Vote
import mixnet.PermutationNetwork
import java.math.BigInteger

import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint
import com.google.protobuf.ByteString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
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
            ElGamal.deserializeCiphertext(encryptedMessage),
            publicKey,
            domainParameters
        )
        val firstRerandomizedMessage = ElGamal.serializeCiphertext(firstRerandomizedCiphertext)
        println("First Rerandomized Encrypted Message: ${firstRerandomizedMessage.data.toHex()}")

        val secondRerandomizedCiphertext = ElGamal.rerandomizeCiphertext(
            ElGamal.deserializeCiphertext(firstRerandomizedMessage),
            publicKey,
            domainParameters
        )
        val secondRerandomizedMessage = ElGamal.serializeCiphertext(secondRerandomizedCiphertext)
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

fun main_for_mixing() {
    val t = 1 // Number of adversaries
    val n = 8 // Number of votes (must be 2t +1 and a power of 2).

    val mixServersManager = MixServersManager(t, n)

    val votes: MutableList<Vote> = mutableListOf(
        Vote(BigInteger.valueOf(0), BigInteger.valueOf(0), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(1), BigInteger.valueOf(1), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(2), BigInteger.valueOf(2), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(3), BigInteger.valueOf(3), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(4), BigInteger.valueOf(0), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(5), BigInteger.valueOf(1), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(6), BigInteger.valueOf(2), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(128))
    )

    println("Initial Votes:")
    votes.forEachIndexed { index, vote ->
        println("Vote $index: ${vote.getCipherText()}")
    }

    val mixedVotes = mixServersManager.apply(votes)

    println("\nFinal Mixed Votes:")
    mixedVotes.forEachIndexed { index, vote ->
        println("Vote $index: ${vote.getCipherText()}")
    }
}