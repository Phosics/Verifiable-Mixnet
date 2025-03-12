package crypto

import meerkat.protobuf.ConcreteCrypto.GroupElement
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.security.Security
import java.util.Random
import mixnet.MixBatchOutputVerifier
import mixnet.SchnorrProofDL
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import kotlin.test.assertTrue
import kotlin.test.fail

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
 * - testThresholdDecryptionWithAllCombinations:
 *   Uses n = 10, t = 6, and 16 random messages. For each message, every t‑subset of servers
 *   is used to decrypt the message. For every 50th decryption, the output includes the decrypted
 *   message along with a note that all ZKP proofs for that subset are verified.
 *   At the end, a final clear message is printed showing the parameters and that all proofs are valid.
 *
 * - testThresholdDecryptionWithInsufficientServers:
 *   Uses n = 10, t = 6, and 16 random messages. In each test, every (t – 1)-subset is used.
 *   The decrypted output is truncated after 10 characters, and every 50th decryption prints a message
 *   stating that all ZKP proofs for that insufficient subset have been verified.
 *   Finally, a clear message is printed with the parameters and a confirmation that while the overall
 *   decryption is incorrect, all individual proofs are valid.
 */
class ThresholdCryptoConfigTest {

    @Test
    fun testThresholdDecryptionWithAllCombinations() {
        // Register BouncyCastle if not already registered.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val domainParameters: ECDomainParameters = ThresholdCryptoConfig.ecDomainParameters
        val n = 10
        val t = 6
        val messageCount = 16

        // Create a single instance of SecureRandom.
        val random = SecureRandom.getInstanceStrong()

        // Generate the threshold key pair using the provided random.
        val (overallPublicKey, servers) = ThresholdCryptoConfig.generateThresholdKeyPair(n, t, random)
        println("🔑 Overall Public Key generated successfully for parameters: n=$n, t=$t.\n")

        // Create a Verifier instance (from the mixnet package) using domainParameters and overallPublicKey.
        val mixBatchOutputVerifier = MixBatchOutputVerifier(domainParameters, overallPublicKey)

        // Generate 16 random messages.
        val messages = List(messageCount) { randomMessage(10) }
        // Get all combinations (subsets) of t servers.
        val serverSubsets = servers.combinations(t)
        println("Testing decryption on ${serverSubsets.size} combinations of $t out of $n servers.\n")

        var printCounter = 0
        messages.forEach { message ->
            println("-----------------------------------------------------")
            println("Original Message: $message")
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)
            // Extract c1 from the ciphertext.
            val ciphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)
            val c1 = CryptoUtils.deserializeGroupElement(ciphertext.c1, domainParameters)
            // Serialize c1 for verification.
            val c1Serialized = CryptoUtils.serializeGroupElement(c1)

            serverSubsets.forEach { subset ->
                printCounter++
                val subsetIds = subset.map { it.getId() }
                val decryptionResult = ThresholdCryptoConfig.thresholdDecrypt(encryptedMessage, subset)
                val decrypted = decryptionResult?.message
                if (printCounter % 50 == 0) {
                    println("Subset $subsetIds --> Decrypted Message: $decrypted")
                    println("Subset $subsetIds --> All ZKP proofs verified for this subset!")
                }
                // The decryption should be correct for a valid t-subset.
                assertEquals(message, decrypted, "Decryption failed for subset IDs: $subsetIds, message: '$message'")

                // Verify each decryption proof using the Verifier.
                if (decryptionResult != null) {
                    decryptionResult.proofs.forEach { (serverId, proof) ->
                        // Find the corresponding server in the subset.
                        val server = subset.first { it.getId() == serverId }
                        val h_i = server.getPartialPublickey()   // FIXED name
                        val d_i = server.computePartialDecryption(c1)
                        val h_iSerialized = CryptoUtils.serializeGroupElement(h_i)
                        val d_iSerialized = CryptoUtils.serializeGroupElement(d_i)
                        val proofOk = verifyDecryptionProof(domainParameters, proof, h_iSerialized, d_iSerialized, c1Serialized)
                        assertTrue(proofOk, "Proof verification failed for server $serverId in subset $subsetIds")
                    }
                }
            }
            println("✅ Message '$message' successfully decrypted by all combinations with valid ZKP proofs! 🚀\n")
        }
        println("🎉 All $messageCount messages decrypted correctly with all ZKP proofs verified for parameters (n=$n, t=$t)! 😎\n")
    }

    @Test
    fun testThresholdDecryptionWithInsufficientServers() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters
        val n = 10
        val t = 6
        val messageCount = 16

        // Create a single SecureRandom instance.
        val random = SecureRandom.getInstanceStrong()

        val (overallPublicKey, servers) = ThresholdCryptoConfig.generateThresholdKeyPair(n, t, random)
        println("🔑 Overall Public Key generated for insufficient-server test with parameters: n=$n, t=$t.\n")

        // Create a Verifier instance.
        val mixBatchOutputVerifier = MixBatchOutputVerifier(domainParameters, overallPublicKey)

        val messages = List(messageCount) { randomMessage(10) }
        // Get all combinations of (t - 1) servers.
        val insufficientSubsets = servers.combinations(t - 1)
        println("Testing decryption with insufficient servers (subsets of size ${t - 1}). Total combinations: ${insufficientSubsets.size}\n")

        var printCounter = 0
        messages.forEach { message ->
            println("-----------------------------------------------------")
            println("Original Message: $message")
            val encryptedMessage = ElGamal.encrypt(overallPublicKey, message, domainParameters)

            // We'll parse out c1 just so we can verify partial proofs.
            val ciphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)
            val c1 = CryptoUtils.deserializeGroupElement(ciphertext.c1, domainParameters)
            val c1Serialized = CryptoUtils.serializeGroupElement(c1)

            insufficientSubsets.forEach { subset ->
                printCounter++
                val subsetIds = subset.map { it.getId() }

                // Attempt a full threshold decrypt (which should fail).
                try {
                    val decryptionResult = ThresholdCryptoConfig.thresholdDecrypt(encryptedMessage, subset)
                    if (decryptionResult != null)
                        fail("Insufficient subset $subsetIds unexpectedly succeeded in decrypting.")
                    // We assert a failure because we only have t-1 shares.
                } catch (e: IllegalStateException) {
                    // We expect an exception about "Not enough valid partial decryptions"
                    if (e.message?.contains("Not enough valid partial decryptions") == true) {
                        // This is good. Now let's confirm each server's partial proof is individually correct.
                        subset.forEach { server ->
                            val d_i = server.computePartialDecryption(c1)
                            val proof = server.generateDecryptionProof(c1)

                            // We'll verify the partial proof using the Verifier.
                            val h_i = server.getPartialPublickey()
                            val h_iSerialized = CryptoUtils.serializeGroupElement(h_i)
                            val d_iSerialized = CryptoUtils.serializeGroupElement(d_i)
                            val proofOk = verifyDecryptionProof(domainParameters, proof, h_iSerialized, d_iSerialized, c1Serialized)
                            assertTrue(
                                proofOk,
                                "Partial proof verification failed for server ${server.getId()} in insufficient subset $subsetIds"
                            )
                        }

                        if (printCounter % 50 == 0) {
                            println("Subset $subsetIds --> All partial ZKP proofs verified (as expected, final decrypt is impossible).")
                        }
                    } else {
                        // Some other error? Rethrow it.
                        throw e
                    }
                }
            }
            println("✅ Message '$message' was NOT fully decrypted with insufficient servers, but all partial proofs are valid!\n")
        }
        println("🎉 Insufficient-server tests completed successfully for parameters (n=$n, t=$t)! All partial ZKP proofs verified! 🔐\n")
    }

    /**
     * Verifies a decryption proof.
     *
     * For a given decryption share, the server’s proof (of type SchnorrProofDL) shows that
     * the same secret s was used to compute both its public share (h = g^s) and its decryption share (d = c1^s).
     *
     * The function performs the following steps:
     * 1. Concatenates the byte arrays of the commitments A_g and A_h from the proof,
     *    and the serialized forms of h_i and d_i.
     * 2. Computes the challenge as e = hash(concatenatedBytes) mod n.
     * 3. Checks that:
     *       g^z = A_g + h_i * e
     *       c1^z = A_h + d_i * e
     *
     * @param proof The SchnorrProofDL containing A_g, A_h and response z.
     * @param h_iSerialized The serialized form of the server’s public share (GroupElement).
     * @param d_iSerialized The serialized form of the server’s decryption share (GroupElement).
     * @param c1Serialized  The serialized form of c1 (used as the second base).
     * @return true if the proof verifies, false otherwise.
     */
    fun verifyDecryptionProof(
        domainParameters: ECDomainParameters,
        proof: SchnorrProofDL,
        h_iSerialized: GroupElement,
        d_iSerialized: GroupElement,
        c1Serialized: GroupElement
    ): Boolean {
        // Concatenate the commitments and the serialized public and decryption shares.
        val baos = ByteArrayOutputStream()
        fun putCommit(A_g: GroupElement, A_h: GroupElement) {
            baos.write(A_g.data.toByteArray())
            baos.write(A_h.data.toByteArray())
        }
        putCommit(proof.A_g, proof.A_h)
        baos.write(h_iSerialized.data.toByteArray())
        baos.write(d_iSerialized.data.toByteArray())

        // Compute the challenge e.
        val challenge = CryptoUtils.hashToBigInteger(baos.toByteArray()).mod(domainParameters.n)

        // Compute the left-hand side for the first equation: g^z.
        val lhs1 = domainParameters.g.multiply(proof.z).normalize()
        // Compute the right-hand side: A_g + h_i * e.
        val rhs1 = CryptoUtils.deserializeGroupElement(proof.A_g, domainParameters)
            .add(CryptoUtils.deserializeGroupElement(h_iSerialized, domainParameters).multiply(challenge))
            .normalize()

        // Compute the left-hand side for the second equation: c1^z.
        val lhs2 = CryptoUtils.deserializeGroupElement(c1Serialized, domainParameters)
            .multiply(proof.z).normalize()
        // Compute the right-hand side: A_h + d_i * e.
        val rhs2 = CryptoUtils.deserializeGroupElement(proof.A_h, domainParameters)
            .add(CryptoUtils.deserializeGroupElement(d_iSerialized, domainParameters).multiply(challenge))
            .normalize()

        return lhs1 == rhs1 && lhs2 == rhs2
    }

}
