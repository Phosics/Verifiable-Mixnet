package crypto

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
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

    // Secure constants
    private const val MIN_KEY_SIZE = 256
    private const val MAX_KEY_SIZE = 521  // Maximum secure EC key size
    private const val DEFAULT_KEY_SIZE = 256

    /**
     * The name of the elliptic curve to be used.
     * Max message length: 256 bits.
     * When using text messages, max text length: 31 Bytes + 1 Byte overhead
     */
    const val EC_CURVE_NAME = "secp256r1"

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
     * Generates a new EC key pair using the specified curve.
     *
     * @return A KeyPair containing the generated public and private keys.
     * @throws NoSuchAlgorithmException if the EC algorithm is not available.
     * @throws InvalidAlgorithmParameterException if the specified curve parameters are invalid.
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC")

        // Use default SecureRandom without manual seeding
        val secureRandom = SecureRandom.getInstanceStrong()

        val ecSpec = ECGenParameterSpec(EC_CURVE_NAME)
        keyPairGenerator.initialize(ecSpec, secureRandom)

        val keyPair = keyPairGenerator.generateKeyPair()

        // Validate generated key
        validateKeyPair(keyPair)

        return keyPair
    }

    // Add key validation
    private fun validateKeyPair(keyPair: KeyPair) {
        val publicKey = keyPair.public as ECPublicKey
        val privateKey = keyPair.private as ECPrivateKey

        // Validate key sizes
        require(privateKey.parameters.curve.fieldSize >= MIN_KEY_SIZE) {
            "Private key size is below minimum required size"
        }

        require(privateKey.parameters.curve.fieldSize <= MAX_KEY_SIZE) {
            "Private key size exceeds maximum allowed size"
        }

        // Validate private key is in range [1, n-1]
        require(privateKey.d >= BigInteger.ONE &&
                privateKey.d < privateKey.parameters.n) {
            "Private key out of valid range"
        }
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
     * Note that this encoding includes the elliptic-curve group parameters.
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

}