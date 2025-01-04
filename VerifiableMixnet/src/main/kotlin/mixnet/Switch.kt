package org.example.mixnet

import org.example.mixnet.Vote
import java.util.function.Function

/**
 * A 2×2 Switch that either reverses or keeps order of two votes.
 * Also intended to do re-encryption + ZKP.
 */
class Switch : Function<List<Vote>, List<Vote>> {
    private var b = 0

    // Set the switching flag
    fun setB(b: Int) {
        require(b == 0 || b == 1) { "Switch value b must be 0 or 1." }
        this.b = b
    }

    fun getB(): Int {return this.b}

    /**
     * Apply the switch to an immutable list of exactly 2 votes.
     * Returns a new immutable list of 2 votes.
     */
    override fun apply(votes: List<Vote>): List<Vote> {
        // Validate size
        require(votes.size == 2) { "Switch requires exactly 2 votes." }

        // Perform the switching operation
        val swapped = if (b == 1) listOf(votes[1], votes[0]) else listOf(votes[0], votes[1])

        // TODO: Implement Zero-Knowledge Proof (ZKP) here

        // TODO: Add the randomness before the return

        return swapped
    }

    // TODO: Add method to generate zero-knowledge proofs for correctness
}