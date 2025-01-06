package org.example.crypto

import com.google.protobuf.ByteString
import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.groupElement
import meerkat.protobuf.rerandomizableEncryptedMessage
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.asn1.DEROctetString

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

        // ASN.1 encode the compressed EC point as an OCTET STRING
        val asn1EncodedPoint = DEROctetString(compressedBytes).encoded

        // Build the GroupElement protobuf message with ASN.1-encoded data
        return GroupElement.newBuilder()
            .setData(ByteString.copyFrom(asn1EncodedPoint))
            .build()
    }

    /**
     * Deserializes a GroupElement Protobuf message into an ECPoint.
     *
     * @param groupElement The GroupElement message to deserialize.
     * @param domainParameters The EC domain parameters.
     * @return The deserialized ECPoint.
     */
    fun deserializeGroupElement(
        groupElement: GroupElement,
        domainParameters: ECDomainParameters
    ): ECPoint {
        val data = groupElement.data.toByteArray()

        // Parse the ASN.1-encoded data
        val asn1Object: ASN1Primitive = try {
            ASN1InputStream(data).use { it.readObject() }
                ?: throw IllegalArgumentException("Empty ASN.1 data.")
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to parse ASN.1 data: ${e.message}", e)
        }

        // Ensure the ASN.1 object is a DEROctetString
        if (asn1Object !is DEROctetString) {
            throw IllegalArgumentException("Expected DEROctetString, found: ${asn1Object.javaClass.simpleName}")
        }

        val compressedPointBytes = asn1Object.octets

        // Decode the compressed EC point
        val ecPoint: ECPoint = try {
            domainParameters.curve.decodePoint(compressedPointBytes)
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to decode EC point: ${e.message}", e)
        }

        return ecPoint
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

//TODO: delete?

//    /**
//     * Serializes an ElGamalCiphertext into bytes.
//     *
//     * @param ciphertext The ElGamalCiphertext to serialize.
//     * @return The serialized byte array.
//     */
//    fun serializeCiphertext(ciphertext: ElGamalCiphertext): ByteArray {
//        return ciphertext.toByteArray()
//    }
//
//    /**
//     * Deserializes bytes into an ElGamalCiphertext.
//     *
//     * @param data The byte array to deserialize.
//     * @return The ElGamalCiphertext.
//     */
//    fun deserializeCiphertext(data: ByteArray): ElGamalCiphertext {
//        return ElGamalCiphertext.parseFrom(data)
//    }
//
//    /**
//     * Extension function to convert ByteString to Hex string.
//     */
//    fun ByteString.toHex(): String {
//        return Hex.toHexString(this.toByteArray())
//    }
}