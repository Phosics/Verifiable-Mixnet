package org.example.crypto

import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec

/**
 * CryptoConfig is responsible for setting up cryptographic parameters
 * and initializing the necessary cryptographic providers.
 */
object CryptoConfig {

    // Initialize Bouncy Castle as a security provider
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    /**
     * The name of the elliptic curve to be used.
     * You can choose a standardized curve like secp256r1 or secp256k1.
     */
    private const val EC_CURVE_NAME = "secp256r1"

    /**
     * The domain parameters for the selected elliptic curve.
     * These include the curve itself, the base point (G), the order (n), and the cofactor (h).
     */
    val ecDomainParameters: ECDomainParameters by lazy {
        val ecParams: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE_NAME)
            ?: throw IllegalArgumentException("Curve $EC_CURVE_NAME not found")
        ECDomainParameters(
            ecParams.curve,
            ecParams.g,
            ecParams.n,
            ecParams.h,
            ecParams.seed
        )
    }

    /**
     * The size of the private key in bits.
     * For secp256r1, the private key size is 256 bits.
     */
    val privateKeySize: Int = ecDomainParameters.n.bitLength()

    /**
     * The size of the public key in bytes.
     * For compressed points, it's typically 33 bytes for secp256r1.
     */
    val publicKeySize: Int = 33 // Compressed form: 1 byte prefix + 32 bytes x-coordinate

    /**
     * Generates a new EC key pair using the specified curve.
     *
     * @return A KeyPair containing the generated public and private keys.
     * @throws NoSuchAlgorithmException if the EC algorithm is not available.
     * @throws InvalidAlgorithmParameterException if the specified curve parameters are invalid.
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC")
        val ecSpec = ECGenParameterSpec(EC_CURVE_NAME)
        keyPairGenerator.initialize(ecSpec, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Retrieves the public key from the given KeyPair.
     *
     * @param keyPair The KeyPair from which to extract the public key.
     * @return The PublicKey object.
     */
    fun getPublicKey(keyPair: KeyPair): PublicKey {
        return keyPair.public
    }

    /**
     * Retrieves the private key from the given KeyPair.
     *
     * @param keyPair The KeyPair from which to extract the private key.
     * @return The PrivateKey object.
     */
    fun getPrivateKey(keyPair: KeyPair): PrivateKey {
        return keyPair.private
    }

    /**
     * Encodes an EC public key into DER-encoded SubjectPublicKeyInfo format as per RFC 3279.
     *
     * @param publicKey The EC public key to encode.
     * @return A byte array containing the DER-encoded public key.
     */
    fun encodePublicKeyDER(publicKey: PublicKey): ByteArray {
        return publicKey.encoded
    }

    /**
     * Decodes a DER-encoded SubjectPublicKeyInfo into an EC PublicKey object.
     *
     * @param encodedPublicKey The DER-encoded public key bytes.
     * @return The PublicKey object.
     * @throws NoSuchAlgorithmException if the EC algorithm is not available.
     * @throws InvalidKeySpecException if the key specification is invalid.
     */
    fun decodePublicKeyDER(encodedPublicKey: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("EC", "BC")
        val keySpec = java.security.spec.X509EncodedKeySpec(encodedPublicKey)
        return keyFactory.generatePublic(keySpec)
    }

    /**
     * Encodes an EC private key into DER format.
     *
     * @param privateKey The EC private key to encode.
     * @return A byte array containing the DER-encoded private key.
     */
    fun encodePrivateKeyDER(privateKey: PrivateKey): ByteArray {
        return privateKey.encoded
    }

    /**
     * Decodes a DER-encoded private key into an EC PrivateKey object.
     *
     * @param encodedPrivateKey The DER-encoded private key bytes.
     * @return The PrivateKey object.
     * @throws NoSuchAlgorithmException if the EC algorithm is not available.
     * @throws InvalidKeySpecException if the key specification is invalid.
     */
    fun decodePrivateKeyDER(encodedPrivateKey: ByteArray): PrivateKey {
        val keyFactory = KeyFactory.getInstance("EC", "BC")
        val keySpec = java.security.spec.PKCS8EncodedKeySpec(encodedPrivateKey)
        return keyFactory.generatePrivate(keySpec)
    }
}