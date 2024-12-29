package org.example.mixnet

import mixnet.Vote
import java.util.function.Function

class Switch : Function<MutableList<Vote>, MutableList<Vote>> {
    private var b = 1

    // Set the switching flag
    fun setB(b: Int) {
        require(b == 0 || b == 1) { "Switch value b must be 0 or 1." }
        this.b = b
    }

    override fun apply(votes: MutableList<Vote>): MutableList<Vote> {
        // Validate size
        require(votes.size == 2) { "Switch requires exactly 2 votes." }

        // Perform the switching operation
        val result = if (b == 1) votes.reversed().toMutableList() else votes.toMutableList()

        // TODO: Implement Zero-Knowledge Proof (ZKP) here

        // TODO: Add the randomness before the return

        return result
    }

    // TODO: Add method to generate zero-knowledge proofs for correctness
}