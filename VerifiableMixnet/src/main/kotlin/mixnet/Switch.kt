package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.BigIntegerUtils
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import org.example.mixnet.ZKPUtils
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
    var zkpOrProof: ZKPOrProof? = null


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
//        this.zkp = generateZKP(votes, swapped, b)
//        val secondAndProof: ZKPAndProof = generateZKP(votes, swapped, r2, r1) // C is always randomized with r1

        this.zkpOrProof = generateZKP(votes, swapped, r1, r2, b)

        return rerandomizedVotes
    }
    /**
     * Generates Zero-Knowledge Proofs (ZKPs) for rerandomized votes in a mixnet.
     *
     * @param votes The original list of votes before rerandomization. Must contain exactly two votes.
     * @param swappedVotes The list of votes after rerandomization. Must contain exactly two votes.
     * @param r1 The randomness used for rerandomizing the first vote.
     * @param r2 The randomness used for rerandomizing the second vote.
     * @return A [ZKPAndProof] object containing the Schnorr proofs for both rerandomized votes.
     *
     * @throws IllegalArgumentException If the number of votes or swappedVotes does not equal two.
     */
    private fun generateZKP(
        votes: List<Vote>,
        swappedVotes: List<Vote>,
        r1: BigInteger,
        r2: BigInteger,
        b: Int
    ): ZKPOrProof {
        require(votes.size == 2) { "Expected exactly 2 original votes." }
        require(swappedVotes.size == 2) { "Expected exactly 2 swapped votes." }

        // Deserialize the votes to extract the ciphertexts
        val aCiphertext = CryptoUtils.unwrapCiphertext(votes[0].getEncryptedMessage())
        val bCiphertext = CryptoUtils.unwrapCiphertext(votes[1].getEncryptedMessage())

        val cCiphertext = CryptoUtils.unwrapCiphertext(swappedVotes[0].getEncryptedMessage())
        val dCiphertext = CryptoUtils.unwrapCiphertext(swappedVotes[1].getEncryptedMessage())

        // Generate the OR-proof with the known random exponents
        val orProof = ZKPUtils.generateOrProof(
            aCiphertext.c1, aCiphertext.c2,
            bCiphertext.c1, bCiphertext.c2,
            cCiphertext.c1, cCiphertext.c2,
            dCiphertext.c1, dCiphertext.c2,
            r1, r2,
            b,
            publicKey,
            domainParameters
        )
        return orProof
    }

}