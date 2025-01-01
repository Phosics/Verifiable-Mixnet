package org.example

import mixnet.MixServer
import mixnet.MixServersManager
import mixnet.Vote
import mixnet.PermutationNetwork
import java.math.BigInteger


fun main() {
    val t = 1 // Number of adversaries
    val n = 8 // Number of votes (must be 2t +1 and a power of 2).

    val mixServersManager = MixServersManager(t, n)

    val votes: MutableList<Vote> = mutableListOf(
        Vote(BigInteger.valueOf(0), BigInteger.valueOf(0), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(1), BigInteger.valueOf(1), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(2), BigInteger.valueOf(2), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(3), BigInteger.valueOf(3), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(4), BigInteger.valueOf(0), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(5), BigInteger.valueOf(1), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(6), BigInteger.valueOf(2), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(128))
    )

    println("Initial Votes:")
    votes.forEachIndexed { index, vote ->
        println("Vote $index: ${vote.getCipherText()}")
    }

    val mixedVotes = mixServersManager.apply(votes)

    println("\nFinal Mixed Votes:")
    mixedVotes.forEachIndexed { index, vote ->
        println("Vote $index: ${vote.getCipherText()}")
    }
}