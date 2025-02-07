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

/**
 * Helper to convert an ECPoint (with known domain parameters) into a PublicKey.
 */
private fun ecPointToPublicKey(point: ECPoint, domainParameters: ECDomainParameters): PublicKey {
    // Since CryptoConfig uses "secp256r1", we fetch its parameter spec.
    val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    val pubSpec = org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec)
    val keyFactory = KeyFactory.getInstance("EC", "BC")
    return keyFactory.generatePublic(pubSpec)
}

/**
 * Extension function to generate all combinations (subsets) of size [k] from the list.
 */
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

/**
 * Helper function to generate a random alphanumeric message of given [length].
 */
private fun randomMessage(length: Int): String {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val random = Random()
    return (1..length).map { chars[random.nextInt(chars.length)] }.joinToString("")
}

/**
 * Test class for threshold encryption/decryption.
 *
 * Uses n = 10 servers and threshold t = 6.
 * For about 20 random messages, it encrypts the message using the overall public key
 * (obtained from threshold key generation) and then verifies that decryption using every
 * combination (subset) of 6 servers recovers the original message.
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

        // Setup threshold key generation.
        val (overallPublicKeyPoint, servers) = ThresholdCoordinator.setupThresholdKeyGeneration(n, t, domainParameters)
        // Convert overall public key (an ECPoint) to a PublicKey for ElGamal encryption.
        val overallPublicKey: PublicKey = ecPointToPublicKey(overallPublicKeyPoint, domainParameters)

        // Generate 20 random messages (each of moderate length).
        val messages = List(20) { randomMessage(10) } // messages of length 10

        // Generate all combinations of t servers out of n.
        val serverSubsets = servers.combinations(t)
        println("Testing decryption on ${serverSubsets.size} combinations of $t out of $n servers.")

        // For each message, encrypt and test decryption with every valid combination.
        messages.forEach { message ->
            // Encrypt using ElGamal encryption with the overall public key.
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)
            // Test each combination.
            serverSubsets.forEach { subset ->
                val decrypted = ThresholdCoordinator.thresholdDecrypt(encryptedMessage, subset, domainParameters)
                assertEquals(
                    message,
                    decrypted,
                    "Decryption failed for server subset IDs: ${subset.map { it.getId() }}, message: '$message'"
                )
            }
        }
    }
}
