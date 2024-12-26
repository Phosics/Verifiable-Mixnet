package org.example.mixnet

import java.math.BigInteger
import java.util.function.Function

class Switch : Function<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>> {
    private var b = 0

    fun setB(b: Int) {
        this.b = b
    }

    override fun apply(inputs: Pair<BigInteger, BigInteger>): Pair<BigInteger, BigInteger> {
        if (b == 0) {
            return Pair(inputs.first, inputs.second)
        }

        return Pair(inputs.second, inputs.first)
    }
}