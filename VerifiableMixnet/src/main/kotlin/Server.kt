import bulltinboard.BulletinBoard
import bulltinboard.TIMEOUT
import bulltinboard.VerifierResult
import mixnet.MixServersManager
import mixnet.VotesReceiver
import org.apache.logging.log4j.LogManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import crypto.CryptoConfig
import crypto.ThresholdCryptoConfig
import crypto.ThresholdDecryptionResult
import java.security.SecureRandom
import java.security.Security

/*
    * The Server class is responsible for running the main server logic.
 */
class Server {
    private val logger = LogManager.getLogger(Server::class.java)
    private val secureRandom = SecureRandom.getInstanceStrong()

    /**
     * The main server loop.
     */
    fun run() {
        logger.info("Starting Kotlin server...")
        Security.addProvider(BouncyCastleProvider())
        val domainParameters = CryptoConfig.ecDomainParameters

        while(true) {
            logger.info("Receiving the BulletinBoard config...")
            val bulletinboard = BulletinBoard()
            bulletinboard.loadBulletinBoardConfig()
            val config = bulletinboard.getConfig()

            logger.info("Generating keys using the decryption servers...")
            val (publicKey, thresholdServers) =
                ThresholdCryptoConfig
                    .generateThresholdKeyPair(config.decryptionServerTotal, config.decryptionServersRequired, secureRandom)

            bulletinboard.sendVotingPublicKey(publicKey)

            logger.info("Closing older polls...")
            bulletinboard.endMix()
            bulletinboard.sendResults(emptyList(), emptyList(), emptyMap())

            logger.info("Waiting for voting to finish...")
            var startMix = bulletinboard.startMix()
            while(!startMix.started) {
                logger.info("Voting has yet to be finished, waiting...")
                Thread.sleep(10 * 1000)

                startMix = bulletinboard.startMix()
            }

            logger.info("Poll ID: ${startMix.pollId}")

            logger.info("Voting finished, getting votes...")
            bulletinboard.loadVotes()

            logger.info("Waiting to mix...")
            Thread.sleep(1 * 1000)

            logger.info("Starting to mix...")
            val serversManager = MixServersManager(publicKey, domainParameters, config.mixServersMalicious, bulletinboard, startMix.pollId)
            serversManager.runServers()
            Thread.sleep((serversManager.getAmountOfServers() * (TIMEOUT + 1)).toLong())

            logger.info("Done mixing")
            bulletinboard.endMix()

            logger.info("Starting to decrypt the votes")
            val votes = VotesReceiver().getVotes(bulletinboard, publicKey, domainParameters, startMix.pollId)
            val decryptionServers = thresholdServers.shuffled().take(config.decryptionServersRequired)
            val thresholdResults : MutableList<ThresholdDecryptionResult?> = mutableListOf()
            for(vote in votes) {
                val thresholdResult = ThresholdCryptoConfig.thresholdDecrypt(vote.getEncryptedMessage(), decryptionServers)
                thresholdResults.add(thresholdResult)
            }

            logger.info("Running verifier...")
            val verifier = Verifier()
            val mixBatchOutputs = bulletinboard.getMixBatchOutputs(startMix.pollId)

            // test1: Computes the SHA-256 hash of the Bulletin Board's public key.
            val BBKeyHash = verifier.test1_GenerateBBKeyHash(config.publicKey)
            logger.info("Test 1 Result: $BBKeyHash")

            // test2: Verifies that the Bulletin Board's general parameters block is authentic.
            val test2Result = verifier.test2_VerifyBBParametersSignature(config.toString(), bulletinboard.getConfigSignature(), config.getPublicKey())
            logger.info("Test 2 Result: $test2Result")

            // test3: Verifies that each mix batch output is produced by an authorized mix server.
            val test3Result = verifier.test3_VerifyMixersAuthorization(serversManager.getAllPublicKeys(), mixBatchOutputs)
            logger.info("Test 3 Result: $test3Result")

            // test4: Verifies that the signed encrypted vote list is authentic.
            val test4Result = verifier.test4_VerifyEncryptedVoteListSignature(bulletinboard.rawVotes, bulletinboard.votesSignature, config.getPublicKey())
            logger.info("Test 4 Result: $test4Result")

            // test5: Verifies that each mix batch output is correctly signed.
            val test5Result = verifier.test5_VerifyMixBatchOutputSignature(mixBatchOutputs.map { it.value })
            logger.info("Test 5 Result: $test5Result")

            // test6: Verifies the Zero-Knowledge Proofs (ZKPs) of the mixing process.
            val test6Result = verifier.test6_VerifyMixersZKP(mixBatchOutputs, domainParameters, publicKey)
            logger.info("Test 6 Result: ${test6Result.size}")

            // test7: Verifies that the first mixer's input equals the signed encrypted vote list.
            val firstMixBatchIndex = test6Result.keys.minOfOrNull { it.toInt() }.toString()
            val test7Result = verifier.test7_VerifyFirstMixerInput(test6Result[firstMixBatchIndex]!!, bulletinboard.votes)
            logger.info("Test 7 Result: $test7Result")

            // test8: Verifies the mixing chain consistency across all mix batches.
            val test8Result = verifier.test8_VerifyMixingChain(test6Result)
            logger.info("Test 8 Result: $test8Result")

            // test9: Verifies the Zero-Knowledge Proofs for the decryption process.
            val test9Result = verifier.test9_VerifyDecryptionZKP(thresholdResults)
            logger.info("Test 9 Result: $test9Result")

            // Post the results to the Bulletin Board
            val verifierResults : MutableList<VerifierResult> = mutableListOf()
            verifierResults.add(VerifierResult(1, BBKeyHash))
            verifierResults.add(VerifierResult(2, test2Result.toString()))
            verifierResults.add(VerifierResult(3, test3Result.toString()))
            verifierResults.add(VerifierResult(4, test4Result.toString()))
            verifierResults.add(VerifierResult(5, test5Result.toString()))
            verifierResults.add(VerifierResult(6, test6Result.size.toString()))
            verifierResults.add(VerifierResult(7, test7Result.toString()))
            verifierResults.add(VerifierResult(8, test8Result.toString()))
            verifierResults.add(VerifierResult(9, test9Result.toString()))

            // Count the results
            val results = thresholdResults.filter { it!!.message != "null" }.map { it!!.message }.groupingBy { it }.eachCount()
            val proofs = thresholdResults.filter { it!!.message != "null" }.map {it!!.toStringProofs()}

            logger.info("Posting the results")
            bulletinboard.sendResults(verifierResults, proofs, results)
        }

    }
}