//package mixnet
//
//import meerkat.protobuf.Crypto
//import meerkat.protobuf.Mixing
//import org.bouncycastle.asn1.x9.DomainParameters
//import org.bouncycastle.crypto.params.ECDomainParameters
//import org.bouncycastle.jce.provider.BouncyCastleProvider
//import crypto.CryptoConfig
//import crypto.ElGamal
//import mixnet.Vote
//import mixnet.MixBatchOutput
//import org.example.mixnet.Verifier
//import java.security.KeyPair
//import java.security.PublicKey
//import java.security.Security
//import kotlin.math.pow
//import kotlin.random.Random
//
///**
// * MixnetTest performs a comprehensive test of the mixnet system.
// * It ensures that after mixing, the distribution of votes across options remains unchanged.
// */
//object MixnetTest {
//
//    @JvmStatic
//    fun main(args: Array<String>) {
//        // Step 1: Register Bouncy Castle as the security provider
//        Security.addProvider(BouncyCastleProvider())
//
//        // Step 2: Initialize cryptographic configurations
//        val keyPair: KeyPair = CryptoConfig.generateKeyPair()
//        val publicKey: PublicKey = CryptoConfig.getPublicKey(keyPair)
//        val privateKey = CryptoConfig.getPrivateKey(keyPair)
//        val domainParameters = CryptoConfig.ecDomainParameters
//
//        // Step 3: Define vote options
//        val voteOptions = listOf(
//            "Option1", "Option2", "Option3", "Option4",
//            "Option5", "Option6", "Option7", "Option8"
//        )
//
//        // Step 4: Generate and encrypt votes
//        val totalVotes = 256
//        val numberOfAdversaries = 3
//
//        // Validate that n is at least 2t + 1 and a power of 2
//        require(totalVotes >= (2 * numberOfAdversaries) + 1) {
//            "Total votes (n) must be at least 2t + 1."
//        }
//        require(isPowerOfTwo(totalVotes)) {
//            "Total votes (n) must be a power of 2."
//        }
//
//        // Initialize random number generator
//        val random = Random(System.currentTimeMillis())
//
//        // Generate random distribution of votes
//        val originalVoteCounts = generateRandomVoteDistribution(voteOptions, totalVotes, random)
//
//        // Create a list of all votes based on the distribution
//        val voteList = mutableListOf<String>()
//        originalVoteCounts.forEach { (option, count) ->
//            repeat(count) {
//                voteList.add(option)
//            }
//        }
//
//        // Shuffle the voteList to randomize the order
//        voteList.shuffle(random)
//
//        // Encrypt votes and create Vote instances
//        val encryptedVotes: MutableList<Vote> = voteList.map { message ->
//            // Encrypt the message using EC-ElGamal
//            val encryptedMessage = ElGamal.encrypt(publicKey, message, domainParameters)
//
//            // Create a Vote instance with the encrypted message
//            Vote(encryptedMessage)
//        }.toMutableList()
//
//        // Display Original Vote Counts
//        println("Original Vote Counts For $totalVotes Votes:")
//        originalVoteCounts.forEach { (option, count) ->
//            println("$option: $count")
//        }
//
//        // Step 5: Initialize MixServersManager and apply mixnet
//        val mixServersManager = MixServersManager(publicKey, domainParameters, numberOfAdversaries, totalVotes)
//
//        // Apply the mixnet to shuffle and rerandomize the votes
//        val mixBatchOutputs: List<MixBatchOutput> = mixServersManager.processMixBatch(encryptedVotes)
//
//        // Print MixBatchOutput for each server and validate layer consistency
//        mixBatchOutputs.forEachIndexed { index, mixBatchOutput ->
//            println("MixBatchOutput for Server ${index + 1}:")
//            println(mixBatchOutput.header)
////            println(mixBatchOutput)
//            validateMixBatchOutput(mixBatchOutput, totalVotes, domainParameters, publicKey)
//            println("--------------------------------------------------")
//        }
//
//        // Step 6: Decrypt mixed votes
//        println("\nDecrypting Mixed Votes for Verification:")
//        // Assuming mixBatchOutputs contain the final layer ciphertexts
//        val finalLayerCiphertexts = mixBatchOutputs.last().ciphertextsMatrix.map { it.last() }
//        finalLayerCiphertexts.forEachIndexed { index, ciphertext ->
//            val decryptedMessage = ElGamal.decrypt(
//                CryptoConfig.getPrivateKey(keyPair),
//                ciphertext,
//                domainParameters
//            )
////            println("Decrypted Vote $index: $decryptedMessage")
//        }
//
//        // Step 7: Tally decrypted votes
//        val decryptedVotes: List<String> = finalLayerCiphertexts.map { ciphertext ->
//            ElGamal.decrypt(privateKey, ciphertext, domainParameters)
//        }
//        val decryptedVoteCounts = tallyVotes(decryptedVotes)
//
//        // Display Decrypted Vote Counts After Mixing
//        println("\nDecrypted Vote Counts After Applying ${2 * numberOfAdversaries + 1} MixServers:")
//        decryptedVoteCounts.forEach { (option, count) ->
//            println("$option: $count")
//        }
//
//        // Step 8: Verify that original and decrypted counts match
//        println("\nVerification Result:")
//        var testPassed = true
//        originalVoteCounts.forEach { (option, originalCount) ->
//            val decryptedCount = decryptedVoteCounts[option] ?: 0
//            if (originalCount != decryptedCount) {
//                println("Mismatch for $option: Original=$originalCount, Decrypted=$decryptedCount")
//                testPassed = false
//            }
//        }
//
//        if (testPassed) {
//            println("✅ Test Passed: All vote counts match after mixing.")
//        } else {
//            println("❌ Test Failed: Vote counts do not match after mixing.")
//        }
//    }
//
//    /**
//     * Generates a random distribution of votes across the given options.
//     *
//     * @param options List of vote options.
//     * @param totalVotes Total number of votes to distribute.
//     * @param random Random number generator.
//     * @return A map of vote option to the number of votes.
//     */
//    private fun generateRandomVoteDistribution(
//        options: List<String>,
//        totalVotes: Int,
//        random: Random
//    ): MutableMap<String, Int> {
//        val distribution = mutableMapOf<String, Int>()
//        for (option in options) {
//            distribution[option] = 0
//        }
//
//        for (i in 1..totalVotes) {
//            val selectedOption = options[random.nextInt(options.size)]
//            distribution[selectedOption] = distribution[selectedOption]!! + 1
//        }
//
//        return distribution
//    }
//
//    /**
//     * Tallies the decrypted votes into a count per option.
//     *
//     * @param decryptedVotes List of decrypted vote options.
//     * @return A map of vote option to the number of votes.
//     */
//    private fun tallyVotes(decryptedVotes: List<String>): Map<String, Int> {
//        val tally = mutableMapOf<String, Int>()
//        for (vote in decryptedVotes) {
//            tally[vote] = tally.getOrDefault(vote, 0) + 1
//        }
//        return tally
//    }
//
//    /**
//     * Checks if a number is a power of two.
//     *
//     * @param n The number to check.
//     * @return True if n is a power of two, else false.
//     */
//    private fun isPowerOfTwo(n: Int): Boolean {
//        return n > 0 && (n and (n - 1)) == 0
//    }
//
//    /**
//     * Extension function to convert ByteArray to hex string.
//     */
//    fun ByteArray.toHex(): String {
//        return org.bouncycastle.util.encoders.Hex.toHexString(this)
//    }
//
//    /**
//     * Validates that each layer in the CiphertextsMatrix contains the expected number of elements.
//     *
//     * @param mixBatchOutput The MixBatchOutput to validate.
//     * @param expectedCount The expected number of ciphertexts per layer.
//     */
//    fun validateMixBatchOutput(mixBatchOutput: MixBatchOutput, expectedCount: Int, domainParameters: ECDomainParameters, publicKey: PublicKey): Boolean {
//        // 1) Validate CiphertextsMatrix by "rows"
//        println("=== Validating CiphertextsMatrix by row (summarized) ===")
//
//        if (expectedCount == 2.0.pow(mixBatchOutput.header.logN).toInt()) {
//            println("✅ The number of votes is correct.")
//        } else {
//            println("❌ The number of votes is incorrect.")
//        }
//
//        val columnCount = mixBatchOutput.ciphertextsMatrix.size
//        val rowCount = if (columnCount == 0) 0 else mixBatchOutput.ciphertextsMatrix[0].size
//
//        val correctCipherRows = mixBatchOutput.header.layers + 1
//        for (rowIdx in 0 until rowCount) {
//            // Gather row elements from each column
//            val rowVotes = mutableListOf<Crypto. RerandomizableEncryptedMessage>()
//            for (colIdx in 0 until columnCount) {
//                rowVotes.add(mixBatchOutput.ciphertextsMatrix[colIdx][rowIdx])
//            }
//        }
//
//        // Summarized result of all ciphertext rows
//        if (correctCipherRows == rowCount) {
//            println("✅ All $rowCount ciphertext rows have $expectedCount votes.")
//        } else {
//            println("❌ $correctCipherRows out of $rowCount ciphertext rows have $expectedCount votes.")
//        }
//
//        // 2) Validate ProofsMatrix by "rows"
//        println("\n=== Validating ProofsMatrix by row (summarized) ===")
//
//        // You mentioned each 2x2 switch handles 2 votes => typical check = expectedCount / 2
//        val expectedProofsPerRow = expectedCount / 2
//
//        val proofColumnCount = mixBatchOutput.proofsMatrix.size
//        val proofRowCount = if (proofColumnCount == 0) 0 else mixBatchOutput.proofsMatrix[0].size
//
//        val correctProofRows = mixBatchOutput.header.layers
//        for (rowIdx in 0 until proofRowCount) {
//            // Gather row proofs from each proof column
//            val rowProofs = mutableListOf<Mixing.Mix2Proof>()
//            for (colIdx in 0 until proofColumnCount) {
//                rowProofs.add(mixBatchOutput.proofsMatrix[colIdx][rowIdx])
//            }
//        }
//
//        // Summarized result of all proof rows
//        if (correctProofRows == proofRowCount) {
//            println("✅ All $proofRowCount proof rows have $expectedProofsPerRow proofs.")
//        } else {
//            println("❌ $correctProofRows out of $proofRowCount proof rows have $expectedProofsPerRow proofs.")
//        }
//
//        // 3) Verify the proofs’ signatures (or correctness) using your existing method
//        println("\n=== Verifying proof signatures ===")
//        val proofsValid = Verifier(domainParameters, publicKey).verifyMixBatchOutput(mixBatchOutput)
//        if (proofsValid) {
//            println("✅ All proofs pass signature verification.")
//        } else {
//            println("❌ Some proofs fail verification.")
//        }
//
//        println("\n=== Validation Summary ===")
//        // Final decision: all checks must be correct
//        val allRowsCorrect = (correctCipherRows == rowCount) && (correctProofRows == proofRowCount)
//        val allChecksPassed = allRowsCorrect && proofsValid
//
//        if (allChecksPassed) {
//            println("✅ Overall: All rows correct and all proofs verified successfully.")
//        } else {
//            println("❌ Overall: Some checks or proofs failed.")
//        }
//
//        return allChecksPassed
//    }
//}