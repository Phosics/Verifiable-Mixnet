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
import org.bouncycastle.jce.interfaces.ECPublicKey
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.*

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
        return RerandomizableEncryptedMessage.newBuilder()
            .setData(ByteString.copyFrom(serializedCiphertext))
            .build()
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
     * Deserializes a GroupElement protobuf message into an ECPoint.
     */
    fun deserializeGroupElementBytes(groupElement: GroupElement, domainParameters: ECDomainParameters): ECPoint {
        return domainParameters.curve.decodePoint(groupElement.data.toByteArray())
    }

    /**
     * Serializes an ECPoint into a byte array.
     */
    fun serializeECPointBytes(point: ECPoint): ByteArray {
        return point.getEncoded(false)
    }

    /**
     * Hashes the input byte array using SHA-256 and converts to BigInteger.
     */
    fun hashToBigInteger(input: ByteArray): BigInteger {
        val md = MessageDigest.getInstance("SHA-256")
        md.reset()
        val digest = md.digest(input)
        return BigInteger(1, digest)
    }

    /**
     * Extracts the ECPoint from a given PublicKey.
     * Assumes that the PublicKey is an instance of ECPublicKey (from Bouncy Castle).
     *
     * @param publicKey The PublicKey to extract the ECPoint from.
     * @return The corresponding ECPoint.
     */
    fun extractECPointFromPublicKey(publicKey: PublicKey): org.bouncycastle.math.ec.ECPoint {
        if (publicKey is ECPublicKey) {
            return publicKey.q.normalize()
        } else {
            throw IllegalArgumentException("PublicKey is not an instance of ECPublicKey")
        }
    }

    fun signData(data : String, privateKey: PrivateKey) : String {
        // Create a Signature instance using SHA256 with RSA algorithm
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(data.toByteArray(Charsets.UTF_8))

        // Generate the digital signature
        val signedBytes = signature.sign()

        // Encode the signature (e.g., using Base64) for easier storage/transmission
        return Base64.getEncoder().encodeToString(signedBytes)
    }

    fun verifySignature(data : String, signatureStr : String, publicKey: PublicKey) : Boolean {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(data.toByteArray(Charsets.UTF_8))

        // Decode the signature from Base64
        val signatureBytes = Base64.getDecoder().decode(signatureStr)

        return signature.verify(signatureBytes)
    }

    /**
     * Converts a hex string to a ByteArray.
     *
     * @param hex The hex string to convert.
     * @return The resulting ByteArray.
     * @throws IllegalArgumentException If the hex string is invalid.
     */
    fun hexStringToByteArray(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Invalid hex string: length must be even." }
        return ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}