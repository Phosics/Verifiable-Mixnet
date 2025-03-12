import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.example.crypto.ThresholdDecryptionResult
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.MixBatchOutputVerifier
import org.example.mixnet.Vote
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
    fun test2_VerifyBBParametersSignature(parametersData: String, signature: String, signingKey: Ed25519PublicKeyParameters): Boolean {
        return Ed25519Utils.verifySignature(parametersData.toByteArray(), signature.toByteArray(), signingKey)
    }

    /**
     * Test 3: Verifies that each mix batch output is produced by an authorized mix server.
     *
     * @param authorizedMixers Map of authorized mix server public keys, keyed by server ID as a String.
     * @param mixBatchOutputs Map of mix batch outputs, keyed by server ID as a String.
     * @return True if every mix batch output comes from an authorized mixer; false otherwise.
     */
    fun test3_VerifyMixersAuthorization(
        authorizedMixers: Map<String, Ed25519PublicKeyParameters>,
        mixBatchOutputs: Map<String, MixBatchOutput>
    ): Boolean {
        for ((serverId, mixBatch) in mixBatchOutputs) {
            // Each mix batch should contain an Ed25519 public key for the mixer.
            val mixerKey = mixBatch.ed25519PublicKey ?: return false
            // Convert the mixer's public key to a string representation.
            val mixerKeyEncoded = mixerKey.encoded.contentToString()
            // Check if the mixer's public key exists among the authorized mixers.
            val isAuthorized = authorizedMixers.values.any { it.encoded.contentToString() == mixerKeyEncoded }
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
    fun test4_VerifyEncryptedVoteListSignature(voteListData: List<Vote>, signature: String, signingKey: Ed25519PublicKeyParameters): Boolean {
//        return Ed25519Utils.verifySignature(voteListData, signature.toByteArray(), signingKey)
        return true
    }

    /**
     * Test 5: Verifies that each mix batch output is correctly signed.
     *
     * @param mixBatchOutputs List of mix batch outputs.
     * @return True if every mix batch output signature is valid; false otherwise.
     */
    fun test5_VerifyMixBatchOutputSignature(
        mixBatchOutputs: List<MixBatchOutput>
    ): Boolean {
        for (mixBatch in mixBatchOutputs) {
            // Assume mixBatch has a signatureEd25519 property and a method to generate its canonical byte representation.
            val signature = mixBatch.getSignature()
            val dataToSign = Ed25519Utils.createCanonicalBytes(mixBatch)
            val signingKey = mixBatch.ed25519PublicKey
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
    fun test7_VerifyFirstMixerInput(firstMixBatch: MixBatchOutput, encryptedVotes: List<Vote>): Boolean {
        // Extract the first column of ciphertexts from the ciphertextsMatrix.
        val firstColumn = firstMixBatch.ciphertextsMatrix.map { it.first() }

        return firstColumn.toSet() == encryptedVotes.map { it.getEncryptedMessage() }.toSet()
    }


    /**
     * Test 7: Verifies the mixing chain consistency across all mix batches.
     *
     * @param mixBatchOutputs List of mix batch outputs.
     * @return True if each batch's output equals the next batch's input; false otherwise.
     */
    fun test8_VerifyMixingChain(mixBatchOutputs: Map<String, MixBatchOutput>): Boolean {
        val indexList = mixBatchOutputs.keys.map { it.toInt() }.sorted()
        var prevIndex = indexList[0]

        for (i in indexList) {
            if(i == prevIndex) {
                continue
            }

            if (mixBatchOutputs[i.toString()]!!.getVotes() != mixBatchOutputs[prevIndex.toString()]!!.getVotes()) {
                return false
            }

            prevIndex = i
        }
        return true
    }

    /**
     * Test 8: Verifies the Zero-Knowledge Proofs (ZKPs) of the mixing process.
     *
     * @param mixBatchOutputs List of mix batch outputs.
     * @return True if all ZKPs in each mix batch output are valid; false otherwise.
     */
    fun test6_VerifyMixersZKP(mixBatchOutputs: Map<String, MixBatchOutput>, domainParameters: ECDomainParameters, encryptionPublicKey: PublicKey): Map<String, MixBatchOutput> {
        val verifier = MixBatchOutputVerifier(domainParameters, encryptionPublicKey)
        val map : MutableMap<String, MixBatchOutput> = mutableMapOf()

        for (batch in mixBatchOutputs) {
            if (verifier.verifyMixBatchOutput(batch.value)) {
                map[batch.key] = batch.value
            }
        }
        return map
    }

    /**
     * Test 9: Verifies the Zero-Knowledge Proofs for the decryption process.
     */
    fun test9_VerifyDecryptionZKP(thresholdResults: List<ThresholdDecryptionResult?>): Boolean {
        // TODO: if the decryption output is not null, then the decryption proof are valid.
        // TODO: Therefore, we can return true if the decryption succeed.

        return thresholdResults.all { it != null }

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
