package crypto

import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.Security
import java.security.SecureRandom

/**
 * ElGamalTest performs comprehensive testing of the EC-ElGamal encryption, rerandomization, and decryption processes.
 * It generates 1,000 random messages, encrypts each, rerandomizes the ciphertext 20 times, decrypts it, and verifies integrity.
 */
object ElGamalTest {

    private const val TEST_ITERATIONS = 1000
    private const val RERANDOMIZATION_COUNT = 20
    const val MIN_MESSAGE_LENGTH = 1 // Minimum number of characters
    const val MAX_MESSAGE_LENGTH = 31 // Maximum number of characters (adjust based on field size)

    @JvmStatic
    fun main(args: Array<String>) {
        // Add Bouncy Castle as a Security Provider
        Security.addProvider(BouncyCastleProvider())

        // Initialize cryptographic configuration
        val keyPair: KeyPair = CryptoConfig.generateKeyPair()
        val publicKey = CryptoConfig.getPublicKey(keyPair)
        val privateKey = CryptoConfig.getPrivateKey(keyPair)
        val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters

        // Initialize counters
        var successCount = 0
        var failureCount = 0

        // Initialize SecureRandom instance for message generation
        val secureRandom = SecureRandom()

        println("Starting EC-ElGamal Encryption Test with $TEST_ITERATIONS messages...")
        println("------------------------------------------------------------")

        for (i in 1..TEST_ITERATIONS) {
            // Generate a random message
            val message = generateRandomAsciiString(MIN_MESSAGE_LENGTH, MAX_MESSAGE_LENGTH, secureRandom)

            try {
                // Encrypt the message
                val encryptedMessage: RerandomizableEncryptedMessage = ElGamal.encrypt(publicKey, message, domainParameters)

                // Rerandomize the ciphertext 20 times
                var rerandomizedMessage = encryptedMessage
                repeat(RERANDOMIZATION_COUNT) { rerandIndex ->
                    val ciphertext = CryptoUtils.unwrapCiphertext(rerandomizedMessage)
                    val rerandomizedCiphertext = ElGamal.rerandomizeCiphertext(ciphertext, publicKey, domainParameters)
                    rerandomizedMessage = CryptoUtils.wrapCiphertext(rerandomizedCiphertext)
                }

                // Decrypt the final ciphertext
                val decryptedMessage: String = ElGamal.decrypt(privateKey, rerandomizedMessage, domainParameters)

                // Verify that the decrypted message matches the original
                if (message == decryptedMessage) {
                    successCount++
                } else {
                    failureCount++
                    println("Mismatch at iteration $i:")
                    println("Original Message   : \"$message\"")
                    println("Decrypted Message : \"$decryptedMessage\"")
                    println("------------------------------------------------------------")
                }

                // Optional: Print progress every 100 iterations
                if (i % 100 == 0) {
                    println("Completed $i/$TEST_ITERATIONS encryptions.")
                }

            } catch (e: IllegalArgumentException) {
                failureCount++
                println("Exception at iteration $i: ${e.message}")
                println("Message: \"$message\"")
                println("------------------------------------------------------------")
            } catch (e: Exception) {
                failureCount++
                println("Unexpected exception at iteration $i: ${e.message}")
                println("Message: \"$message\"")
                println("------------------------------------------------------------")
            }
        }

        // Final report
        println("------------------------------------------------------------")
        println("Test Completed.")
        println("Total Messages Tested   : $TEST_ITERATIONS")
        println("Successful Encryptions  : $successCount")
        println("Failed Encryptions      : $failureCount")
    }

    /**
     * Generates a random ASCII string with length between minLength and maxLength.
     *
     * @param minLength Minimum length of the generated string.
     * @param maxLength Maximum length of the generated string.
     * @param random    SecureRandom instance for randomness.
     * @return A random ASCII string.
     */
    fun generateRandomAsciiString(minLength: Int, maxLength: Int, random: SecureRandom): String {
        val length = random.nextInt(maxLength - minLength + 1) + minLength
        val chars = ('!'..'~') // Printable ASCII characters excluding space
        return (1..length)
            .map { chars.random() }
            .joinToString("")
    }
}