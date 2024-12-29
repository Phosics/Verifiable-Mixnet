package mixnet

import java.math.BigInteger

data class Vote(
    private val cipherText: BigInteger,
    private val gr: BigInteger,
    private val modulus: BigInteger // TODO: added by Guy, ensure correct arithmetic calculation
) {
    fun getCipherText(): BigInteger = cipherText

    fun getGR(): BigInteger = gr

    fun addRandomness(randomness: BigInteger): Vote {
        // Note: add randomness return a new object, and doesn't change the original one
        val newCipherText = cipherText.multiply(randomness).mod(modulus)
        val newGR = gr.multiply(randomness).mod(modulus)
        return copy(cipherText = newCipherText, gr = newGR)
    }

}