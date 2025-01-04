package org.example.mixnet

import org.bouncycastle.crypto.params.ECDomainParameters
import java.util.function.Function
import java.security.PublicKey

/**
 * A 2×2 Switch that either reverses or keeps the order of two votes.
 * Also performs rerandomization to ensure unlinkability.
 * Zero-Knowledge Proof (ZKP) implementation is intended but not included here.
 */
class Switch(private val publicKey: PublicKey, private val domainParameters: ECDomainParameters) : Function<List<Vote>, List<Vote>> {

    private var b = 0

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
    fun getB(): Int {
        return this.b
    }

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

        // TODO: Implement Zero-Knowledge Proof (ZKP) here to prove correct switching without revealing b
        // Placeholder for ZKP implementation

        // Rerandomize each vote to ensure unlinkability
        val rerandomizedVotes = swapped.map { vote ->
            vote.addRandomness(publicKey, domainParameters)
        }

        return rerandomizedVotes
    }

    // TODO: Add method to generate zero-knowledge proofs for correctness
}