package mixnet

import java.math.BigInteger

class Vote (private val cipherText: BigInteger, private val gr: BigInteger) {
    fun getCipherText(): BigInteger {
        return cipherText
    }

    fun getGR(): BigInteger {
        return gr
    }

    fun addRandomness(randomness: BigInteger) {
        cipherText.multiply(randomness)
        gr.multiply(randomness)
    }
}