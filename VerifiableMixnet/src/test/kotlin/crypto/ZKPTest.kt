package crypto

import crypto.ElGamalTest.MAX_MESSAGE_LENGTH
import crypto.ElGamalTest.MIN_MESSAGE_LENGTH
import crypto.ElGamalTest.generateRandomAsciiString
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import org.example.crypto.ElGamal
import org.example.mixnet.Switch
import org.example.mixnet.Verifier
import org.example.mixnet.Vote
import org.example.mixnet.ZKPUtils
import java.security.SecureRandom

class ZKPTest {
    object SwitchTest {

        @JvmStatic
        fun main(args: Array<String>) {
            testSingleSwitch()
        }

        /**
         * 1) Generate a named-curve key pair on secp256k1
         * 2) Build domain parameters
         * 3) Create 2 random "votes"
         * 4) Create Switch, set b=0 or b=1
         * 5) Apply => new votes, plus an OR-proof
         * 6) Verify the OR-proof
         */
        fun testSingleSwitch() {
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

            // 4) Create Switch
            val switch = Switch(publicKey, domainParameters)
            // We'll pick b=1 => swapped
            switch.setB(1)

            // 5) Apply
            val originalVotes = listOf(voteA, voteB)
            val newVotes = switch.apply(originalVotes)
            val orProof = switch.zkpOrProof
            require(orProof != null) { "No OR-proof generated" }

            // 6) Verify
            val verifier = Verifier(domainParameters, publicKey)

            // Unwrap
            // Deserialize the votes to extract the ciphertexts
            val aCiphertext = CryptoUtils.unwrapCiphertext(originalVotes[0].getEncryptedMessage())
            val bCiphertext = CryptoUtils.unwrapCiphertext(originalVotes[1].getEncryptedMessage())

            val cCiphertext = CryptoUtils.unwrapCiphertext(newVotes[0].getEncryptedMessage())
            val dCiphertext = CryptoUtils.unwrapCiphertext(newVotes[1].getEncryptedMessage())

            val ok = verifier.verifyOrProof(
                orProof,
                aCiphertext.c1, aCiphertext.c2,
                bCiphertext.c1, bCiphertext.c2,
                cCiphertext.c1, cCiphertext.c2,
                dCiphertext.c1, dCiphertext.c2
            )
            println("OR-Proof verification result: $ok")
        }

    }
    object test2{

    }
}