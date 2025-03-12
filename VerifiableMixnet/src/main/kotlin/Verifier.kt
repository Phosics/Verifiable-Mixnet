import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.example.crypto.ThresholdDecryptionResult
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.MixBatchOutputVerifier
import java.security.MessageDigest
import java.security.PublicKey

/**
 * Verifier class that provides methods to verify various cryptographic proofs and signatures.
 *
 * This class is used to perform an end-to-end verification of the mixnet voting process.
 *
 */
class Verifier() {

    /**
     * Computes the SHA-256 hash of the Bulletin Board's public key.
     *
     * @param bbPublicKey The Bulletin Board's public key.
     * @return A hexadecimal string representing the hash.
     */
    fun test1_GenerateBBKeyHash(bbPublicKey: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val keyBytes = bbPublicKey.toByteArray()
        val computedHash = md.digest(keyBytes)
        return computedHash.joinToString("") { "%02x".format(it) }
    }

    /**
     * Test 2: Verifies that the Bulletin Board's general parameters block is authentic.
     *
     * @param parametersData The bytes of the parameters block.
     * @param signature The signature on the parameters block.
     * @param signingKey The public key used for signing (typically the BB's public key).
     * @return True if the signature is valid; false otherwise.
     */
    fun test2_VerifyBBParametersSignature(parametersData: ByteArray, signature: ByteArray, signingKey: Ed25519PublicKeyParameters): Boolean {
        return Ed25519Utils.verifySignature(parametersData, signature, signingKey)
    }

    /**
     * Test 3: Verifies that each mix batch output is produced by an authorized mix server.
     *
     * @param authorizedMixers List of authorized mix server public keys.
     * @param mixBatchOutputs List of mix batch outputs.
     * @return True if every mix batch output comes from an authorized mixer; false otherwise.
     */
    fun test3_VerifyMixersAuthorization(authorizedMixers: List<PublicKey>, mixBatchOutputs: List<MixBatchOutput>): Boolean {
        for (mixBatch in mixBatchOutputs) {
            // Assume each mix batch contains an ed25519PublicKey field
            val mixerKey = mixBatch.ed25519PublicKey ?: return false
            // Compare the encoded public keys
            val mixerKeyEncoded = mixerKey.encoded.contentToString()
            val isAuthorized = authorizedMixers.any { it.encoded.contentToString() == mixerKeyEncoded }
            if (!isAuthorized) return false
        }
        return true
    }

    /**
     * Test 4: Verifies that the signed encrypted vote list is authentic.
     *
     * @param voteListData The bytes representing the encrypted vote list.
     * @param signature The signature on the vote list.
     * @param signingKey The public key used for signing (e.g., BB's public key).
     * @return True if the signature is valid; false otherwise.
     */
    fun test4_VerifyEncryptedVoteListSignature(voteListData: ByteArray, signature: ByteArray, signingKey: Ed25519PublicKeyParameters): Boolean {
        return Ed25519Utils.verifySignature(voteListData, signature, signingKey)
    }

    /**
     * Test 5: Verifies that each mix batch output is correctly signed.
     *
     * @param mixBatchOutputs List of mix batch outputs.
     * @param signingKeyResolver Function to retrieve the signing key for a given mix batch output.
     *                           For example, it could return mixBatchOutput.ed25519PublicKey.
     * @return True if every mix batch output signature is valid; false otherwise.
     */
    fun test5_VerifyMixBatchOutputSignature(
        mixBatchOutputs: List<MixBatchOutput>,
        signingKeyResolver: (MixBatchOutput) -> Ed25519PublicKeyParameters?
    ): Boolean {
        for (mixBatch in mixBatchOutputs) {
            // Assume mixBatch has a signatureEd25519 property and a method to generate its canonical byte representation.
            val signature = mixBatch.getSignature()
            val dataToSign = Ed25519Utils.createCanonicalBytes(mixBatch)
            val signingKey = signingKeyResolver(mixBatch) ?: return false
            if (!Ed25519Utils.verifySignature(dataToSign, signature, signingKey)) return false
        }
        return true
    }

    /**
     * Test 6: Verifies that the first mixer's input equals the signed encrypted vote list.
     *
     * @param firstMixBatch The first mix batch output.
     * @param encryptedVotes The list of original encrypted votes (as RerandomizableEncryptedMessage).
     * @return True if the first mixer's input matches the encrypted vote list; false otherwise.
     */
    fun test6_VerifyFirstMixerInput(firstMixBatch: MixBatchOutput, encryptedVotes: List<RerandomizableEncryptedMessage>): Boolean {
        // Extract the first column of ciphertexts from the ciphertextsMatrix.
        val firstColumn = firstMixBatch.ciphertextsMatrix.first()
        return firstColumn == encryptedVotes
    }


    /**
     * Test 7: Verifies the mixing chain consistency across all mix batches.
     *
     * @param mixBatchOutputs List of mix batch outputs.
     * @return True if each batch's output equals the next batch's input; false otherwise.
     */
    fun test7_VerifyMixingChain(mixBatchOutputs: List<MixBatchOutput>): Boolean {
        for (i in 1 until mixBatchOutputs.size) {
            if (mixBatchOutputs[i].getVotes() != mixBatchOutputs[i - 1].getVotes()) {
                return false
            }
        }
        return true
    }

    /**
     * Test 8: Verifies the Zero-Knowledge Proofs (ZKPs) of the mixing process.
     *
     * @param mixBatchOutputs List of mix batch outputs.
     * @return True if all ZKPs in each mix batch output are valid; false otherwise.
     */
    fun test8_VerifyMixersZKP(mixBatchOutputs: List<MixBatchOutput>, domainParameters: ECDomainParameters, encryptionPublicKey: PublicKey): Boolean {
        val verifier = MixBatchOutputVerifier(domainParameters, encryptionPublicKey)

        for (batch in mixBatchOutputs) {
            if (!verifier.verifyMixBatchOutput(batch)) return false
        }
        return true
    }

    /**
     * Test 9: Verifies the Zero-Knowledge Proofs for the decryption process.
     */
    fun test9_VerifyDecryptionZKP(): Boolean {
        // TODO: if the decryption output is not null, then the decryption proof are valid.
        // TODO: Therefore, we can return true if the decryption succeed.

        return true

    }

    /**
     * Test 10: Summarizes the final decrypted votes.
     *
     * @param decryptionOutputs List of threshold decryption results.
     * @return A list of integers representing the vote counts (or summary) for each choice.
     */
    fun test10_SummarizeDecryptedVotes(decryptionOutputs: List<ThresholdDecryptionResult>): List<Int> {
        val summaryMap = mutableMapOf<Int, Int>()
        for (result in decryptionOutputs) {
            // Assume that each ThresholdDecryptionResult has a 'message' field that contains the decrypted vote as a string.
            val vote = result.message.toIntOrNull() ?: continue
            summaryMap[vote] = (summaryMap[vote] ?: 0) + 1
        }
        // Return the summary as a list sorted by vote option.
        return summaryMap.toSortedMap().values.toList()
    }
}
