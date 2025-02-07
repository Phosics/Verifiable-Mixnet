package crypto

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Security
import java.util.Random
import java.util.concurrent.TimeUnit
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import org.example.crypto.ThresholdCoordinator
import kotlin.test.assertNotEquals

// Helper to convert an ECPoint into a PublicKey (assumes "secp256r1" curve)
private fun ecPointToPublicKey(point: ECPoint, domainParameters: ECDomainParameters): PublicKey {
    val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    val pubSpec = org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec)
    val keyFactory = KeyFactory.getInstance("EC", "BC")
    return keyFactory.generatePublic(pubSpec)
}

// Extension function to compute all combinations (subsets) of size k from a list.
private fun <T> List<T>.combinations(k: Int): List<List<T>> {
    val result = mutableListOf<List<T>>()
    fun combine(start: Int, current: List<T>) {
        if (current.size == k) {
            result.add(current)
            return
        }
        for (i in start until this.size) {
            combine(i + 1, current + this[i])
        }
    }
    combine(0, listOf())
    return result
}

// Helper to generate a random alphanumeric message of given length.
private fun randomMessage(length: Int): String {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val random = Random()
    return (1..length).map { chars[random.nextInt(chars.length)] }.joinToString("")
}

/**
 * Test class for threshold encryption/decryption.
 *
 * Two tests are provided:
 * 1. testThresholdDecryptionWithAllCombinations: Uses n = 10 servers and threshold t = 6.
 *    For 20 random messages, each is encrypted using the overall public key and then
 *    decrypted using every combination of t out of 10 servers. For sanity checking,
 *    every 50th decryption prints the subset IDs and the decrypted message.
 * 2. testThresholdDecryptionWithInsufficientServers: Shows that using any combination
 *    of fewer than t servers (here t - 1) does not correctly decrypt the message.
 */
class ThresholdEncryptionTest {

    @Test
    fun testThresholdDecryptionWithAllCombinations() {
        // Ensure BouncyCastle is registered.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }

        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters
        val n = 10
        val t = 6

        // Set up threshold key generation.
        val (overallPublicKeyPoint, servers) = ThresholdCoordinator.setupThresholdKeyGeneration(n, t, domainParameters)
        // Convert overall public key (an ECPoint) to a PublicKey for ElGamal encryption.
        val overallPublicKey: PublicKey = ecPointToPublicKey(overallPublicKeyPoint, domainParameters)

        println("🔑 Overall Public Key generated successfully!")

        // Generate 20 random messages (each of moderate length).
        val messages = List(20) { randomMessage(10) } // messages of length 10

        // Generate all combinations of t servers out of n.
        val serverSubsets = servers.combinations(t)
        println("Testing decryption on ${serverSubsets.size} combinations of $t out of $n servers.\n")

        var printCounter = 0
        messages.forEach { message ->
            println("-----------------------------------------------------")
            println("Original Message: $message")
            // Encrypt the message using standard ElGamal encryption.
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)
            serverSubsets.forEach { subset ->
                printCounter++
                val subsetIds = subset.map { it.getId() }
                val decrypted = ThresholdCoordinator.thresholdDecrypt(encryptedMessage, subset, domainParameters)
                if (printCounter % 50 == 0) { // Print every 50th decryption for sanity check.
                    println("Subset $subsetIds --> Decrypted Message: $decrypted")
                }
                assertEquals(
                    message,
                    decrypted,
                    "Decryption failed for server subset IDs: $subsetIds, message: '$message'"
                )
            }
            println("✅ Message '$message' successfully decrypted by all combinations! 🚀\n")
        }
        println("🎉 All messages decrypted correctly with every combination! 😎\n")
    }

    @Test
    fun testThresholdDecryptionWithInsufficientServers() {
        // Ensure BouncyCastle is registered.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }

        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters
        val n = 10
        val t = 6

        // Set up threshold key generation.
        val (overallPublicKeyPoint, servers) = ThresholdCoordinator.setupThresholdKeyGeneration(n, t, domainParameters)
        // Convert overall public key (an ECPoint) to a PublicKey for ElGamal encryption.
        val overallPublicKey: PublicKey = ecPointToPublicKey(overallPublicKeyPoint, domainParameters)

        println("🔑 Overall Public Key generated for insufficient-server test!")

        // Generate a few random messages.
        val messages = List(5) { randomMessage(10) }

        // Generate all combinations of (t - 1) servers out of n.
        val insufficientSubsets = servers.combinations(t - 1)
        println("Testing decryption with insufficient servers (using subsets of size ${t - 1}). Total combinations: ${insufficientSubsets.size}\n")

        var printCounter = 0
        messages.forEach { message ->
            println("-----------------------------------------------------")
            println("Original Message: $message")
            // Encrypt the message.
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)
            insufficientSubsets.forEach { subset ->
                printCounter++
                val subsetIds = subset.map { it.getId() }
                val decrypted = ThresholdCoordinator.thresholdDecrypt(encryptedMessage, subset, domainParameters)
                if (printCounter % 50 == 0) { // Print every 50th decryption for sanity check.
                    println("Subset $subsetIds --> Decrypted Message: $decrypted")
                }
                // Assert that decryption does not yield the original message.
                assertNotEquals(
                    message,
                    decrypted,
                    "Insufficient decryption unexpectedly succeeded for server subset IDs: $subsetIds, message: '$message'"
                )
            }
            println("✅ Message '$message' was NOT correctly decrypted with insufficient servers. 🔒\n")
        }
        println("🎉 Insufficient-server tests completed successfully! 🔐\n")
    }
}