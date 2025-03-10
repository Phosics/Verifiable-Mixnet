/**
 * A self-contained example demonstrating:
 *  1) Creating 4 dummy Votes.
 *  2) Creating a simple MixServer that mixes and signs a MixBatchOutput using Ed25519.
 *  3) Verifying the signature locally (no bulletin board, no JUnit).
 *
 * NOTE: This is a minimal example and omits actual ElGamal encryption logic.
 *       It reuses the provided Vote class and simulates the rest.
 */

package example

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.mixnet.Vote
import java.security.SecureRandom
import java.security.Security
import kotlin.math.log2

// --------------------------------------------------
// 1) Minimal domain-parameter config & utilities
// --------------------------------------------------

object SimpleCryptoConfig {
    // For demonstration, we skip a real EC domain parameter init
    // and just store a placeholder. If you have an actual ECPublicKey,
    // you can adapt your real code here.
    val random = SecureRandom.getInstanceStrong()

    // This is a dummy domain parameter placeholder
    // In real usage, you'd get a valid ECDomainParameters from your code
    val ecDomainParameters: ECDomainParameters by lazy {
        // Dummy placeholders - do not use in production
        // If your real code uses "secp256r1", fetch from your existing CryptoConfig
        ECDomainParameters(null, null, null, null)
    }
}

/**
 * Utility for Ed25519 sign/verify of a "MixBatchOutput".
 * In real code, you'd store this in a separate file, e.g. Ed25519Utils.kt.
 */
object Ed25519Utils {

    fun signMixBatchOutput(batch: MixBatchOutput, privateKey: Ed25519PrivateKeyParameters): MixBatchOutput {
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        val data = batch.toCanonicalBytes()
        signer.update(data, 0, data.size)
        val signature = signer.generateSignature()
        return batch.copy(signatureEd25519 = signature)
    }

    fun verifyMixBatchOutput(batch: MixBatchOutput, publicKey: Ed25519PublicKeyParameters): Boolean {
        val sig = batch.signatureEd25519 ?: return false
        val verifier = Ed25519Signer()
        verifier.init(false, publicKey)
        val data = batch.toCanonicalBytes()
        verifier.update(data, 0, data.size)
        return verifier.verifySignature(sig)
    }
}

// --------------------------------------------------
// 2) Minimal "MixBatchOutput" data class
//    Enough to store 4 votes & a signature
// --------------------------------------------------

data class MixBatchOutput(
    val votes: List<Vote>,
    val signatureEd25519: ByteArray? = null
) {
    /**
     * Convert the batch data to a canonical byte array (excluding the signature).
     * Here we just concatenate each vote's data for simplicity.
     */
    fun toCanonicalBytes(): ByteArray {
        // Real code might do Protobuf serialization, etc.
        val sb = StringBuilder()
        votes.forEachIndexed { i, v ->
            sb.append("Vote$i:${v.getEncryptedMessage().data.toStringUtf8()}")
        }
        return sb.toString().toByteArray()
    }
}

// --------------------------------------------------
// 3) Minimal "MixServer" that creates 4 dummy votes,
//    random permutation, and signs the output
// --------------------------------------------------

class MixServer(private val n: Int) {

    // Ed25519 keys
    private val ed25519PrivateKey: Ed25519PrivateKeyParameters
    val ed25519PublicKey: Ed25519PublicKeyParameters

    init {
        // Bouncy Castle for cryptographic operations
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }

        require(n > 0 && (n and (n - 1)) == 0) { "n must be a power of 2." }

        // Generate Ed25519 key pair
        val privateBytes = ByteArray(32)
        SimpleCryptoConfig.random.nextBytes(privateBytes)
        ed25519PrivateKey = Ed25519PrivateKeyParameters(privateBytes, 0)
        ed25519PublicKey = ed25519PrivateKey.generatePublicKey()
        println("MixServer with n=$n created Ed25519 key pair.")
    }

    /**
     * Runs the server: creates dummy votes, shuffles them, and signs the batch.
     */
    fun runServer(): MixBatchOutput {
        // 1) Create 4 dummy votes (since n=4).
        val votes = createDummyVotes(n)

        // 2) "Shuffle" them with a random permutation.
        val perm = randomPermutation(n)
        val shuffledVotes = perm.map { votes[it] }

        // 3) Build the MixBatchOutput with the shuffled votes
        val unsignedBatch = MixBatchOutput(shuffledVotes)

        // 4) Sign with Ed25519
        val signedBatch = Ed25519Utils.signMixBatchOutput(unsignedBatch, ed25519PrivateKey)
        println("MixServer: Created and signed a MixBatchOutput with ${signedBatch.votes.size} votes.")
        return signedBatch
    }

    private fun createDummyVotes(count: Int): List<Vote> {
        // Each vote: we create a dummy "encrypted message" (in real code, you'd do real ElGamal encryption)
        return (1..count).map { i ->
            val dummyMsg = "DummyVote$i"
            val dummyBytes = dummyMsg.toByteArray()
            // We'll build a minimal RerandomizableEncryptedMessage with these bytes
            val rMsg = meerkat.protobuf.Crypto.RerandomizableEncryptedMessage.newBuilder()
                .setData(com.google.protobuf.ByteString.copyFrom(dummyBytes))
                .build()
            Vote(rMsg)
        }
    }

    /**
     * Random permutation using Fisher-Yates
     */
    private fun randomPermutation(n: Int): IntArray {
        val perm = IntArray(n) { it }
        for (i in (n - 1) downTo 1) {
            val j = SimpleCryptoConfig.random.nextInt(i + 1)
            val tmp = perm[i]
            perm[i] = perm[j]
            perm[j] = tmp
        }
        return perm
    }
}

// --------------------------------------------------
// 4) A simple main() function to demonstrate usage
// --------------------------------------------------

fun main() {
    val n = 4
    println("We want to test a single MixServer with n=$n.")

    for (i in 1..10) {
        println("\n--- Test run $i ---")

        // Create and run the MixServer
        val mixServer = MixServer(n)
        val signedBatch = mixServer.runServer()

        // Now verify the signature locally
        val publicKey = mixServer.ed25519PublicKey
        val signatureOk = Ed25519Utils.verifyMixBatchOutput(signedBatch, publicKey)
        println("Signature verified? $signatureOk")

        // Additional check: ensure the batch has exactly 4 votes
        println("Batch has ${signedBatch.votes.size} votes.")
    }

    println("Done.")
}
