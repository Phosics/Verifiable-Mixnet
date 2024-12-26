package org.example.mixnet

import mixnet.Vote
import java.util.function.Function

class Switch : Function<MutableList<Vote>, MutableList<Vote>> {
    private var b = 1

    fun setB(b: Int) {
        this.b = b
    }

    override fun apply(votes: MutableList<Vote>): MutableList<Vote> {
        // TODO: Add shuffle
        // TODO: Validate both lists are in size 2
        if (b == 1) {
            votes.reverse()
        }

        return votes
        // TODO: Add zero-knowledge proof
    }
}