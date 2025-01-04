package org.example.crypto

import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.groupElement
import meerkat.protobuf.rerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.math.ec.ECPoint
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.math.BigInteger

/**
 * ElGamal provides encryption and decryption functionalities using EC-ElGamal scheme.
 */
object ElGamal {

    private val secureRandom = SecureRandom()

    /**
     * Encrypts a message ECPoint using the provided ElGamal public key.
     *
     * @param publicKey The ElGamal public key.
     * @param message The message to encrypt as an ECPoint.
     * @param domainParameters The EC domain parameters.
     * @return A RerandomizableEncryptedMessage containing the ciphertext.
     */
    fun encrypt(
        publicKey: PublicKey,
        message: ECPoint,
        domainParameters: ECDomainParameters
    ): RerandomizableEncryptedMessage {
        // Extract Q from publicKey
        val keyFactory = KeyFactory.getInstance("EC", "BC")
        val x509KeySpec = X509EncodedKeySpec(publicKey.encoded)
        val pubKey = keyFactory.generatePublic(x509KeySpec) as ECPublicKey
        val qPoint: ECPoint = pubKey.q

        // Choose random k ∈ [1, n-1]
        val k = BigIntegerUtils.randomBigInteger(domainParameters.n, secureRandom)

        // Compute C1 = k * G
        val c1: ECPoint = domainParameters.g.multiply(k).normalize()

        // Compute C2 = M + k * Q
        val c2: ECPoint = message.add(qPoint.multiply(k)).normalize()

        // Serialize c1 and c2 into GroupElement Protobuf messages
        val serializedC1: GroupElement = CryptoUtils.serializeGroupElement(c1)
        val serializedC2: GroupElement = CryptoUtils.serializeGroupElement(c2)

        // Build ElGamalCiphertext using the builder pattern
        val elGamalCiphertext: ElGamalCiphertext = ElGamalCiphertext.newBuilder()
            .setC1(serializedC1)
            .setC2(serializedC2)
            .build()

        // Wrap into RerandomizableEncryptedMessage
        return CryptoUtils.wrapCiphertext(elGamalCiphertext)
    }

    /**
     * Decrypts a RerandomizableEncryptedMessage using the provided private key.
     *
     * @param privateKey The EC private key.
     * @param encryptedMessage The RerandomizableEncryptedMessage to decrypt.
     * @param domainParameters The EC domain parameters.
     * @return The decrypted message as an ECPoint.
     */
    fun decrypt(
        privateKey: PrivateKey,
        encryptedMessage: RerandomizableEncryptedMessage,
        domainParameters: ECDomainParameters
    ): ECPoint {
        // Parse the ElGamalCiphertext
        val elGamalCiphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)

        // Deserialize c1 and c2
        val c1: ECPoint = CryptoUtils.deserializeGroupElement(elGamalCiphertext.c1, domainParameters)
        val c2: ECPoint = CryptoUtils.deserializeGroupElement(elGamalCiphertext.c2, domainParameters)

        // Compute M = C2 - d * C1
        val d: BigInteger = (privateKey as ECPrivateKey).d
        val dC1: ECPoint = c1.multiply(d).normalize()
        val mPoint: ECPoint = c2.subtract(dC1).normalize()

        return mPoint
    }

    /**
     * Serializes an ElGamalCiphertext into a RerandomizableEncryptedMessage.
     *
     * @param ciphertext The ElGamalCiphertext to serialize.
     * @return The RerandomizableEncryptedMessage containing the ciphertext.
     */
    fun serializeCiphertext(ciphertext: ElGamalCiphertext): RerandomizableEncryptedMessage {
        return CryptoUtils.wrapCiphertext(ciphertext)
    }

    /**
     * Deserializes a RerandomizableEncryptedMessage into an ElGamalCiphertext.
     *
     * @param encryptedMessage The RerandomizableEncryptedMessage to deserialize.
     * @return The ElGamalCiphertext.
     */
    fun deserializeCiphertext(encryptedMessage: RerandomizableEncryptedMessage): ElGamalCiphertext {
        return CryptoUtils.unwrapCiphertext(encryptedMessage)
    }
}

/**
 * BigIntegerUtils provides utility functions for BigInteger operations.
 */
object BigIntegerUtils {

    /**
     * Generates a random BigInteger in the range [1, max - 1].
     *
     * @param max The upper bound (exclusive).
     * @param random The SecureRandom instance to use.
     * @return A random BigInteger.
     */
    fun randomBigInteger(max: BigInteger, random: SecureRandom): BigInteger {
        var result: BigInteger
        do {
            result = BigInteger(max.bitLength(), random)
        } while (result < BigInteger.ONE || result >= max)
        return result
    }
}