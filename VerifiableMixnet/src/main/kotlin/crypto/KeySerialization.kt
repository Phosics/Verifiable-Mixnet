package org.example.crypto

import com.google.protobuf.kotlin.toByteString
import meerkat.protobuf.ConcreteCrypto.ElGamalPublicKey
import org.example.crypto.CryptoConfig
import java.security.PublicKey

/**
 * KeySerialization provides functions to handle ElGamalPublicKey Protobuf messages.
 */
object KeySerialization {

    /**
     * Creates an ElGamalPublicKey Protobuf message from a PublicKey.
     *
     * @param publicKey The PublicKey to encode.
     * @return The ElGamalPublicKey Protobuf message.
     */
    fun createElGamalPublicKey(publicKey: PublicKey): ElGamalPublicKey {
        return ElGamalPublicKey.newBuilder()
            .setSubjectPublicKeyInfo(CryptoConfig.encodePublicKeyDER(publicKey).toByteString())
            .build()
    }

    /**
     * Extracts a PublicKey from an ElGamalPublicKey Protobuf message.
     *
     * @param elGamalPublicKey The ElGamalPublicKey Protobuf message.
     * @return The PublicKey.
     */
    fun extractPublicKey(elGamalPublicKey: ElGamalPublicKey): PublicKey {
        val encodedKey = elGamalPublicKey.subjectPublicKeyInfo.toByteArray()
        return CryptoConfig.decodePublicKeyDER(encodedKey)
    }
}