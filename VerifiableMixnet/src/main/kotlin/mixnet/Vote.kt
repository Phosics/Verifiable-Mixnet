package org.example.mixnet

import org.example.crypto.ElGamal
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoUtils
import java.math.BigInteger
import java.security.PublicKey

/**
 * Vote represents an encrypted vote using the EC-ElGamal encryption scheme.
 *
 * @param encryptedMessage The encrypted vote encapsulated in a RerandomizableEncryptedMessage.
 */
data class Vote(
    private val encryptedMessage: RerandomizableEncryptedMessage
) {
    /**
     * Retrieves the encrypted message.
     *
     * @return The RerandomizableEncryptedMessage representing the ciphertext.
     */
    fun getEncryptedMessage(): RerandomizableEncryptedMessage = encryptedMessage

    /**
     * Rerandomizes the ciphertext by adding additional randomness.
     *
     * @param publicKey The ElGamal public key used for rerandomization.
     * @param domainParameters The EC domain parameters.
     * @return A new Vote instance with rerandomized ciphertext.
     */
    fun addRandomness(publicKey: PublicKey, domainParameters: ECDomainParameters, r: BigInteger): Vote {
        // Deserialize the current ciphertext
        val elGamalCiphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)

        // Rerandomize the ciphertext using EC-ElGamal rerandomization
        val rerandomizedCiphertext = ElGamal.rerandomizeCiphertext(elGamalCiphertext, publicKey, domainParameters, r)

        // Serialize the rerandomized ciphertext back to RerandomizableEncryptedMessage
        val rerandomizedMessage = CryptoUtils.wrapCiphertext(rerandomizedCiphertext)

        // Return a new Vote instance with the rerandomized ciphertext
        return copy(encryptedMessage = rerandomizedMessage)
    }

}