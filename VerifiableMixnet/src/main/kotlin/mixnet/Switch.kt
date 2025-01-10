package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.BigIntegerUtils
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.function.Function
import java.security.PublicKey
import java.security.SecureRandom

/**
 * A 2×2 Switch that either reverses or keeps the order of two votes.
 * Also performs rerandomization to ensure unlinkability.
 * Zero-Knowledge Proof (ZKP) implementation is intended but not included here.
 */
class Switch(
    private val publicKey: PublicKey,
    private val domainParameters: ECDomainParameters
) : Function<List<Vote>, List<Vote>> {

    private var b = 0
    var zkp: Mixing.Mix2Proof? = null
        private set

    /**
     * Sets the switching flag.
     * @param b An integer where 0 means no switch and 1 means switch the votes.
     */
    fun setB(b: Int) {
        require(b == 0 || b == 1) { "Switch value b must be 0 or 1." }
        this.b = b
    }

    /**
     * Retrieves the current value of the switching flag.
     * @return The value of b.
     */
    fun getB(): Int = b

    /**
     * Applies the switch to an immutable list of exactly 2 votes.
     * Performs switching based on flag b and rerandomizes the votes.
     * @param votes A list containing exactly 2 Vote instances.
     * @return A new list of 2 rerandomized Vote instances.
     */
    override fun apply(votes: List<Vote>): List<Vote> {
        // Validate the size of the input list
        require(votes.size == 2) { "Switch requires exactly 2 votes." }

        // Perform the switching operation based on the flag b
        val swapped = if (b == 1) listOf(votes[1], votes[0]) else listOf(votes[0], votes[1])

        // Generate two separate random nonces for each swapped output
        val secureRandom = SecureRandom.getInstanceStrong()
        val r1 = BigIntegerUtils.randomBigInteger(domainParameters.n, secureRandom)
        val r2 = BigIntegerUtils.randomBigInteger(domainParameters.n, secureRandom)

        // Rerandomize the votes with the generated randoms
        val rerandomizedVotes = swapped.mapIndexed { index, vote ->
            val r = if (index == 0) r1 else r2
            vote.addRandomness(publicKey, domainParameters, r)
        }

        // TODO: Implement Zero-Knowledge Proof (ZKP) here to prove correct switching without revealing b
        // Generate ZKP to prove correct switching without revealing b
        this.zkp = generateZKP(votes, swapped, b)

        return rerandomizedVotes
    }

    // TODO: Add method to generate zero-knowledge proofs for correctness


    private fun generateZKP(
        votes: List<Vote>,
        swappedVotes: List<Vote>,
        b: Int
    ): Mixing.Mix2Proof {
        // Deserialize the votes to extract the ciphertexts
        val aCiphertext = CryptoUtils.unwrapCiphertext(votes[0].getEncryptedMessage())
        val bCiphertext = CryptoUtils.unwrapCiphertext(votes[1].getEncryptedMessage())

        val cCiphertext = CryptoUtils.unwrapCiphertext(swappedVotes[0].getEncryptedMessage())
        val dCiphertext = CryptoUtils.unwrapCiphertext(swappedVotes[1].getEncryptedMessage())

//        // Generate proofs for each vote pair
//        val proof0 = generateSingleZKP(aCiphertext.c1, aCiphertext.c2, cCiphertext.c1, cCiphertext.c2)
//        val proof1 = generateSingleZKP(bCiphertext.c1, bCiphertext.c2, dCiphertext.c1, dCiphertext.c2)

        // Package proofs into Mix2Proof
        return Mixing.Mix2Proof.newBuilder()
            .setFirstMessage(Mixing.Mix2Proof.FirstMessage.getDefaultInstance())
            .setFinalMessage(Mixing.Mix2Proof.FinalMessage.getDefaultInstance())
            .setLocation(Mixing.Mix2Proof.Location.newBuilder()
                .setLayer(0)        // Example value; set appropriately
                .setSwitchIdx(0)    // Example value; set appropriately
                .setOut0(0)         // Example value; set appropriately
                .setOut1(1)         // Example value; set appropriately
                .build())
            .build()
    }

    /**
     * Generates the Schnorr Discrete-Log-Equality Proof.
     * Proves that log_g(X) = log_h(Y), where:
     * X = c1 / a1
     * Y = c2 / a2
     *
     * @param a1 The first component of the original ciphertext.
     * @param a2 The second component of the original ciphertext.
     * @param c1 The first component of the rerandomized ciphertext.
     * @param c2 The second component of the rerandomized ciphertext.
     * @param r The randomness used in rerandomization.
     * @return An instance of SchnorrProofDL containing A_g, A_h, and z.
     */
    private fun generateSingleZKP(
        a1: GroupElement,
        a2: GroupElement,
        c1: GroupElement,
        c2: GroupElement,
        r: BigInteger
    ): SchnorrProofDL {
        // Deserialize GroupElements to ECPoints
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)

        // Compute X = c1 - a1 and Y = c2 - a2
        val X = c1Point.add(a1Point.negate()).normalize()
        val Y = c2Point.add(a2Point.negate()).normalize()

        // Deserialize h (public key) into ECPoint
        val hPoint = CryptoUtils.extractECPointFromPublicKey(publicKey)

        // Commit Phase: pick random t and compute A_g = g^t, A_h = h^t
        val t = BigIntegerUtils.randomBigInteger(domainParameters.n, SecureRandom.getInstanceStrong())

        val A_g = domainParameters.g.multiply(t).normalize()
        val A_h = hPoint.multiply(t).normalize()

        // Serialize A_g and A_h
        val A_gSerialized = CryptoUtils.serializeGroupElement(A_g)
        val A_hSerialized = CryptoUtils.serializeGroupElement(A_h)

        val A_gBytes = A_gSerialized.data.toByteArray()
        val A_hBytes = A_hSerialized.data.toByteArray()

        // Serialize X and Y
        val XSerialized = CryptoUtils.serializeGroupElement(X)
        val YSerialized = CryptoUtils.serializeGroupElement(Y)

        val XBytes = XSerialized.data.toByteArray()
        val YBytes = YSerialized.data.toByteArray()

        // Prepare challenge input using Fiat-Shamir heuristic: A_g || A_h || X || Y
        val challengeInput = ByteBuffer.allocate(
            A_gBytes.size +
                    A_hBytes.size +
                    XBytes.size +
                    YBytes.size
        )
            .put(A_gBytes)
            .put(A_hBytes)
            .put(XBytes)
            .put(YBytes)
            .array()

        // Compute the challenge c = H(A_g || A_h || X || Y) mod q
        val c = CryptoUtils.hashToBigInteger(challengeInput).mod(domainParameters.n)

        // Compute the response z = t + c * r mod q
        val z = t.add(c.multiply(r)).mod(domainParameters.n)

        return SchnorrProofDL(
            A_g = A_gSerialized,
            A_h = A_hSerialized,
            z = z
        )
    }
}