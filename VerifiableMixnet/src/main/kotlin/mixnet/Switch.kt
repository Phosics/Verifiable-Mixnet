package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.BigIntegerUtils
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import java.math.BigInteger
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

        // Rerandomize each vote to ensure unlinkability
        val rerandomizedVotes = swapped.map { vote ->
            vote.addRandomness(publicKey, domainParameters)
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

        // Generate proofs for each vote pair
        val proof0 = generateSingleZKP(aCiphertext.c1, aCiphertext.c2, cCiphertext.c1, cCiphertext.c2)
        val proof1 = generateSingleZKP(bCiphertext.c1, bCiphertext.c2, dCiphertext.c1, dCiphertext.c2)

        // Package proofs into Mix2Proof
        return Mixing.Mix2Proof.newBuilder()
//            .addProofs(
//                Mixing.Proof.newBuilder()
//                    .setR(ByteString.copyFrom(proof0.first))
//                    .setS(ByteString.copyFrom(proof0.second))
//                    .build()
//            )
//            .addProofs(
//                Mixing.Proof.newBuilder()
//                    .setR(ByteString.copyFrom(proof1.first))
//                    .setS(ByteString.copyFrom(proof1.second))
//                    .build()
//            )
//            .build()
    }

    private fun generateSingleZKP(
        a1: GroupElement,
        a2: GroupElement,
        c1: GroupElement,
        c2: GroupElement
    ): Pair<ByteArray, ByteArray> {
        // Deserialize GroupElements to ECPoints
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters) // Corrected

        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)

        // Compute c1 / a1 and c2 / a2
        // In elliptic curves, division is equivalent to multiplying by the inverse
        val c1DivA1 = c1Point.add(a1Point.negate()).normalize()
        val c2DivA2 = c2Point.add(a2Point.negate()).normalize()

        val x = publicKey // TODO: convert to point

        // Generate a random nonce r in [1, n-1]
        val secureRandom = SecureRandom.getInstanceStrong() // TODO: Change it to a static getter on the mix server
        val r = BigIntegerUtils.randomBigInteger(domainParameters.n, secureRandom)

        // Compute u = g^r
        val u = domainParameters.g.multiply(r).normalize()

        // Serialize u
        val uBytes = CryptoUtils.serializeECPointBytes(u)

        // Compute the challenge c using Fiat-Shamir heuristic (hash of u)
        val c = CryptoUtils.hashToBigInteger(uBytes).mod(domainParameters.n)

        // Compute z = r + c * x mod n
        val z = r.add(c.multiply(x)).mod(domainParameters.n)

        // Serialize z
        val zBytes = z.toByteArray()

        // Return the proof as (u, z)
        return Pair(uBytes, zBytes)
    }
}