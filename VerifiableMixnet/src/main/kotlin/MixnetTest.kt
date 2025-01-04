package org.example

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import org.example.mixnet.Vote
import mixnet.MixServersManager
import java.security.KeyPair
import java.security.Security
import kotlin.random.Random

/**
 * MixnetTest performs a comprehensive test of the mixnet system.
 * It ensures that after mixing, the distribution of votes across options remains unchanged.
 */
object MixnetTest {

    @JvmStatic
    fun main(args: Array<String>) {
        // Step 1: Register Bouncy Castle as the security provider
        Security.addProvider(BouncyCastleProvider())

        // Step 2: Initialize cryptographic configurations
        val keyPair: KeyPair = CryptoConfig.generateKeyPair()
        val publicKey = CryptoConfig.getPublicKey(keyPair)
        val privateKey = CryptoConfig.getPrivateKey(keyPair)
        val domainParameters = CryptoConfig.ecDomainParameters

        // Step 3: Define vote options
        val voteOptions = listOf(
            "Option1", "Option2", "Option3", "Option4",
            "Option5", "Option6", "Option7", "Option8"
        )

        // Step 4: Generate and encrypt votes
        val totalVotes = 256
        val numberOfAdversaries = 5

        // Validate that n is at least 2t + 1 and a power of 2
        require(totalVotes >= (2 * numberOfAdversaries) + 1) {
            "Total votes (n) must be at least 2t + 1."
        }
        require(isPowerOfTwo(totalVotes)) {
            "Total votes (n) must be a power of 2."
        }

        // Initialize random number generator
        val random = Random(System.currentTimeMillis())

        // Generate random distribution of votes
        val originalVoteCounts = generateRandomVoteDistribution(voteOptions, totalVotes, random)

        // Create a list of all votes based on the distribution
        val voteList = mutableListOf<String>()
        originalVoteCounts.forEach { (option, count) ->
            repeat(count) {
                voteList.add(option)
            }
        }

        // Shuffle the voteList to randomize the order
        voteList.shuffle(random)

        // Encrypt votes and create Vote instances
        val encryptedVotes: MutableList<Vote> = voteList.map { message ->
            // Encrypt the message using EC-ElGamal
            val encryptedMessage = ElGamal.encrypt(publicKey, message, domainParameters)

            // Create a Vote instance with the encrypted message
            Vote(encryptedMessage)
        }.toMutableList()

        // Display Original Vote Counts
        println("Original Vote Counts For $totalVotes Votes:")
        originalVoteCounts.forEach { (option, count) ->
            println("$option: $count")
        }

        // Step 5: Initialize MixServersManager and apply mixnet
        val mixServersManager = MixServersManager(publicKey, domainParameters, numberOfAdversaries, totalVotes)
//        mixServersManager.setPublicKey(publicKey)

        // Apply the mixnet to shuffle and rerandomize the votes
        val mixedVotes = mixServersManager.apply(encryptedVotes)

//        // Display Final Mixed Votes
//        println("\nFinal Mixed Votes:")
//        mixedVotes.forEachIndexed { index, vote: Vote ->
//            println("Vote $index:")
//            println("Encrypted Message: ${vote.getEncryptedMessage().data.toHex()}")
//            println("--------------------------------------------------")
//        }

        // Step 6: Decrypt mixed votes
        val decryptedVotes: List<String> = mixedVotes.map { vote: Vote ->
            ElGamal.decrypt(privateKey, vote.getEncryptedMessage(), domainParameters)
        }

        // Step 7: Tally decrypted votes
        val decryptedVoteCounts = tallyVotes(decryptedVotes)

        // Display Decrypted Vote Counts After Mixing
        println("\nDecrypted Vote Counts After Applying ${2*numberOfAdversaries+1} MixServers:")
        decryptedVoteCounts.forEach { (option, count) ->
            println("$option: $count")
        }

        // Step 8: Verify that original and decrypted counts match
        println("\nVerification Result:")
        var testPassed = true
        originalVoteCounts.forEach { (option, originalCount) ->
            val decryptedCount = decryptedVoteCounts[option] ?: 0
            if (originalCount != decryptedCount) {
                println("Mismatch for $option: Original=$originalCount, Decrypted=$decryptedCount")
                testPassed = false
            }
        }

        if (testPassed) {
            println("✅ Test Passed: All vote counts match after mixing.")
        } else {
            println("❌ Test Failed: Vote counts do not match after mixing.")
        }
    }

    /**
     * Generates a random distribution of votes across the given options.
     *
     * @param options List of vote options.
     * @param totalVotes Total number of votes to distribute.
     * @param random Random number generator.
     * @return A map of vote option to the number of votes.
     */
    private fun generateRandomVoteDistribution(
        options: List<String>,
        totalVotes: Int,
        random: Random
    ): MutableMap<String, Int> {
        val distribution = mutableMapOf<String, Int>()
        for (option in options) {
            distribution[option] = 0
        }

        for (i in 1..totalVotes) {
            val selectedOption = options[random.nextInt(options.size)]
            distribution[selectedOption] = distribution[selectedOption]!! + 1
        }

        return distribution
    }

    /**
     * Tallies the decrypted votes into a count per option.
     *
     * @param decryptedVotes List of decrypted vote options.
     * @return A map of vote option to the number of votes.
     */
    private fun tallyVotes(decryptedVotes: List<String>): Map<String, Int> {
        val tally = mutableMapOf<String, Int>()
        for (vote in decryptedVotes) {
            tally[vote] = tally.getOrDefault(vote, 0) + 1
        }
        return tally
    }

    /**
     * Checks if a number is a power of two.
     *
     * @param n The number to check.
     * @return True if n is a power of two, else false.
     */
    private fun isPowerOfTwo(n: Int): Boolean {
        return n > 0 && (n and (n - 1)) == 0
    }
}