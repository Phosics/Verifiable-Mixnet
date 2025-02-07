package crypto

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.security.Security
import java.util.Random
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import org.example.crypto.ThresholdCryptoConfig
import kotlin.test.assertNotEquals

// Extension function: returns all subsets of size k from a list.
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

// Helper function: generates a random alphanumeric string of the given length.
private fun randomMessage(length: Int): String {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val random = Random()
    return (1..length).map { chars[random.nextInt(chars.length)] }.joinToString("")
}

/**
 * Test class for ThresholdCryptoConfig.
 *
 * - testThresholdDecryptionWithAllCombinations: Using n = 10 and t = 6, 20 random messages are encrypted
 *   with the overall public key (generated via ThresholdCryptoConfig.generateThresholdKeyPair). Then, every
 *   t‑subset of servers is used to decrypt the message. For sanity checking, every 50th decryption prints the
 *   subset IDs and decrypted message.
 *
 * - testThresholdDecryptionWithInsufficientServers: Demonstrates that using any subset of (t – 1) servers does not
 *   correctly decrypt the ciphertext.
 */
class ThresholdCryptoConfigTest {

    @Test
    fun testThresholdDecryptionWithAllCombinations() {
        // Register BouncyCastle if not already registered.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters
        val n = 10
        val t = 6

        // Generate the threshold key pair.
        val (overallPublicKey, servers) = ThresholdCryptoConfig.generateThresholdKeyPair(n, t)
        println("🔑 Overall Public Key generated successfully!\n")

        // Generate 20 random messages.
        val messages = List(20) { randomMessage(10) }
        // Get all combinations (subsets) of t servers from the full server list.
        val serverSubsets = servers.combinations(t)
        println("Testing decryption on ${serverSubsets.size} combinations of $t out of $n servers.\n")

        var printCounter = 0
        messages.forEach { message ->
            println("-----------------------------------------------------")
            println("Original Message: $message")
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)
            serverSubsets.forEach { subset ->
                printCounter++
                val subsetIds = subset.map { it.getId() }
                val decrypted = ThresholdCryptoConfig.thresholdDecrypt(encryptedMessage, subset)
                if (printCounter % 50 == 0) {
                    println("Subset $subsetIds --> Decrypted Message: $decrypted")
                }
                assertEquals(message, decrypted, "Decryption failed for subset IDs: $subsetIds, message: '$message'")
            }
            println("✅ Message '$message' successfully decrypted by all combinations! 🚀\n")
        }
        println("🎉 All messages decrypted correctly with every combination! 😎\n")
    }

    @Test
    fun testThresholdDecryptionWithInsufficientServers() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters
        val n = 10
        val t = 6

        val (overallPublicKey, servers) = ThresholdCryptoConfig.generateThresholdKeyPair(n, t)
        println("🔑 Overall Public Key generated for insufficient-server test!\n")

        // Generate 5 random messages.
        val messages = List(5) { randomMessage(10) }
        // Get all combinations of (t - 1) servers.
        val insufficientSubsets = servers.combinations(t - 1)
        println("Testing decryption with insufficient servers (subsets of size ${t - 1}). Total combinations: ${insufficientSubsets.size}\n")

        var printCounter = 0
        messages.forEach { message ->
            println("-----------------------------------------------------")
            println("Original Message: $message")
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)
            insufficientSubsets.forEach { subset ->
                printCounter++
                val subsetIds = subset.map { it.getId() }
                val decrypted = ThresholdCryptoConfig.thresholdDecrypt(encryptedMessage, subset)
                if (printCounter % 50 == 0) {
                    println("Subset $subsetIds --> Decrypted Message: ${decrypted.substring(0, 10)}...")
                }
                // Expect the decryption to be incorrect.
                assertNotEquals(message, decrypted, "Insufficient decryption unexpectedly succeeded for subset IDs: $subsetIds, message: '$message'")
            }
            println("✅ Message '$message' was NOT correctly decrypted with insufficient servers. 🔒\n")
        }
        println("🎉 Insufficient-server tests completed successfully! 🔐\n")
    }
}