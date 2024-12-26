package org.example

import mixnet.MixServer
import mixnet.Vote
import java.math.BigInteger

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
fun main() {
    var mixServer = MixServer(4)
    print(mixServer)

    var votes : MutableList<Vote> = mutableListOf()
    votes.add(Vote(BigInteger.ONE, BigInteger.ONE))
    votes.add(Vote(BigInteger.TWO, BigInteger.TWO))
    votes.add(Vote(BigInteger.valueOf(3), BigInteger.valueOf(3)))
    votes.add(Vote(BigInteger.valueOf(4), BigInteger.valueOf(4)))

    var res = mixServer.apply(votes)
    print(res)
}