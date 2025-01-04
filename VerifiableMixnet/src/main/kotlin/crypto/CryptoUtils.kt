package org.example.crypto

import com.google.protobuf.ByteString
import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.groupElement
import meerkat.protobuf.rerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint

/**
 * CryptoUtils provides utility functions for serializing and deserializing
 * elliptic curve points and handling Protobuf messages.
 */
object CryptoUtils {

    /**
     * Serializes an ECPoint into a GroupElement Protobuf message.
     *
     * @param ecPoint The ECPoint to serialize.
     * @return The serialized GroupElement message.
     */
    fun serializeGroupElement(ecPoint: ECPoint): GroupElement {
        // Ensure the point is in compressed form
        val compressedBytes = ecPoint.getEncoded(true) // true for compressed
        return groupElement {
            data = ByteString.copyFrom(compressedBytes)
        }
    }

    /**
     * Deserializes a GroupElement Protobuf message into an ECPoint.
     *
     * @param groupElement The GroupElement message to deserialize.
     * @param domainParameters The EC domain parameters.
     * @return The deserialized ECPoint.
     */
    fun deserializeGroupElement(groupElement: GroupElement, domainParameters: ECDomainParameters): ECPoint {
        val data = groupElement.data.toByteArray()
        // Decode the ASN.1-encoded point
        return domainParameters.curve.decodePoint(data)
    }

    /**
     * Wraps an ElGamalCiphertext into a RerandomizableEncryptedMessage.
     *
     * @param ciphertext The ElGamalCiphertext to wrap.
     * @return The RerandomizableEncryptedMessage containing the ciphertext.
     */
    fun wrapCiphertext(ciphertext: ElGamalCiphertext): RerandomizableEncryptedMessage {
        val serializedCiphertext = ciphertext.toByteArray()
        return rerandomizableEncryptedMessage {
            data = ByteString.copyFrom(serializedCiphertext)
        }
    }

    /**
     * Unwraps a RerandomizableEncryptedMessage into an ElGamalCiphertext.
     *
     * @param encryptedMessage The RerandomizableEncryptedMessage to unwrap.
     * @return The ElGamalCiphertext contained within.
     */
    fun unwrapCiphertext(encryptedMessage: RerandomizableEncryptedMessage): ElGamalCiphertext {
        return ElGamalCiphertext.parseFrom(encryptedMessage.data.toByteArray())
    }

    /**
     * Serializes an ElGamalCiphertext into bytes.
     *
     * @param ciphertext The ElGamalCiphertext to serialize.
     * @return The serialized byte array.
     */
    fun serializeCiphertext(ciphertext: ElGamalCiphertext): ByteArray {
        return ciphertext.toByteArray()
    }

    /**
     * Deserializes bytes into an ElGamalCiphertext.
     *
     * @param data The byte array to deserialize.
     * @return The ElGamalCiphertext.
     */
    fun deserializeCiphertext(data: ByteArray): ElGamalCiphertext {
        return ElGamalCiphertext.parseFrom(data)
    }
}