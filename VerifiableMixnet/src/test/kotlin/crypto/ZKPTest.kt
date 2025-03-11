package crypto

import crypto.ElGamalTest.MAX_MESSAGE_LENGTH
import crypto.ElGamalTest.MIN_MESSAGE_LENGTH
import crypto.ElGamalTest.generateRandomAsciiString
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import org.example.crypto.ElGamal
import org.example.mixnet.Switch
import org.example.mixnet.MixBatchOutputVerifier
import org.example.mixnet.Vote
import org.example.mixnet.ZKPUtils
import java.security.SecureRandom

class ZKPTest {
    object SwitchTest {

        @JvmStatic
        fun main(args: Array<String>) {
            println("========== Testing OR-Proof with switchFlag = 0 ==========")
            testSingleSwitch(switchFlag = 0)
            println("\n========== Testing OR-Proof with switchFlag = 1 ==========")
            testSingleSwitch(switchFlag = 1)
            println("\n========== Running Multiple Iterations ==========")
            runMultipleIterations(10)
        }

        /**
         * Generates a key pair, creates random votes, constructs the switch proof using the given switchFlag,
         * and then verifies the OR-proof.
         */
        fun testSingleSwitch(switchFlag: Int): Boolean {
            // 1) Generate key pair
            val keyPair = CryptoConfig.generateKeyPair()
            val publicKey = keyPair.public

            // 2) Domain parameters
            val domainParameters = CryptoConfig.ecDomainParameters

            // 3) Create two random "votes"
            val secureRandom = SecureRandom()
            val messageA = generateRandomAsciiString(MIN_MESSAGE_LENGTH, MAX_MESSAGE_LENGTH, secureRandom)
            val encryptedMessageA: RerandomizableEncryptedMessage = ElGamal.encrypt(publicKey, messageA, domainParameters)
            val voteA = Vote(encryptedMessageA)

            val messageB = generateRandomAsciiString(MIN_MESSAGE_LENGTH, MAX_MESSAGE_LENGTH, secureRandom)
            val encryptedMessageB: RerandomizableEncryptedMessage = ElGamal.encrypt(publicKey, messageB, domainParameters)
            val voteB = Vote(encryptedMessageB)

            // 4) Create a Switch and set its switch flag.
            val switch = Switch(publicKey, domainParameters, secureRandom)
            switch.setB(switchFlag)  // sets the secret switch flag (0 or 1)

            // 5) Apply the switch to obtain new votes and the OR-proof.
            val originalVotes = listOf(voteA, voteB)
            val newVotes = switch.apply(originalVotes)
            val orProof = switch.zkpOrProof
            require(orProof != null) { "No OR-proof generated" }

            // 6) Verification: Unwrap the ciphertexts.
            val aCiphertext = CryptoUtils.unwrapCiphertext(originalVotes[0].getEncryptedMessage())
            val bCiphertext = CryptoUtils.unwrapCiphertext(originalVotes[1].getEncryptedMessage())
            val cCiphertext = CryptoUtils.unwrapCiphertext(newVotes[0].getEncryptedMessage())
            val dCiphertext = CryptoUtils.unwrapCiphertext(newVotes[1].getEncryptedMessage())

            // Verify the OR-proof.
            val ok = MixBatchOutputVerifier(domainParameters, publicKey).verifySingleOrProof(
                ZKPUtils.serializeZKP(orProof),
                aCiphertext.c1, aCiphertext.c2,
                bCiphertext.c1, bCiphertext.c2,
                cCiphertext.c1, cCiphertext.c2,
                dCiphertext.c1, dCiphertext.c2
            )
            println("OR-Proof verification result for switchFlag = $switchFlag: $ok")
            return ok
        }

        /**
         * Runs multiple iterations of the switch test (with a random switch flag each time),
         * counts the number of successful iterations, and prints a summary message.
         */
        fun runMultipleIterations(iterations: Int) {
            val secureRandom = SecureRandom()
            var successCount = 0
            for (i in 1..iterations) {
                println("---- Iteration $i ----")
                val switchFlag = if (secureRandom.nextBoolean()) 0 else 1
                val ok = testSingleSwitch(switchFlag)
                if (ok) {
                    successCount++
                }
                println()
            }
            println("✅ Total iterations: $iterations")
            println("✅ Successful verifications: $successCount")
            if (successCount == iterations) {
                println("🎉👍 All tests passed successfully! 👍🎉")
            } else {
                println("⚠️ Some tests failed. Please review the logs. ⚠️")
            }
        }
    }

}
