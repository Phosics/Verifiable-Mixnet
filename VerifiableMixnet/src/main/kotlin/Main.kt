package org.example

import mixnet.MixServer
import mixnet.Vote
import mixnet.PermutationNetwork
import java.math.BigInteger


fun main() {
    val mixServer = MixServer(4)

    val votes: MutableList<Vote> = mutableListOf(
        Vote(BigInteger.valueOf(0), BigInteger.valueOf(0), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(1), BigInteger.valueOf(1), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(2), BigInteger.valueOf(2), BigInteger.valueOf(128)),
        Vote(BigInteger.valueOf(3), BigInteger.valueOf(3), BigInteger.valueOf(128)) ,
//        Vote(BigInteger.valueOf(4), BigInteger.valueOf(0), BigInteger.valueOf(128)),
//        Vote(BigInteger.valueOf(5), BigInteger.valueOf(1), BigInteger.valueOf(128)),
//        Vote(BigInteger.valueOf(6), BigInteger.valueOf(2), BigInteger.valueOf(128)),
//        Vote(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(128))
    )

    println("Initial Votes:")
    votes.forEachIndexed { index, vote -> println("Vote $index: ${vote.getCipherText()}") }

//    var result = mixServer.apply(votes)
//
//    println("\nFirst Shuffled Votes:")
//    result.forEachIndexed { index, vote -> println("Vote $index: ${vote.getCipherText()}") }

    mixServer.configureRandomly()

    val result = mixServer.apply(votes)

    println("\nFinal Shuffled Votes:")
    result.forEachIndexed { index, vote -> println("Vote $index: ${vote.getCipherText()}") }

}