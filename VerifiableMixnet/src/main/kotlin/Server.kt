import bulltinboard.BulletinBoard
import bulltinboard.TIMEOUT
import mixnet.MixServersManager
import mixnet.VotesReceiver
import org.apache.logging.log4j.LogManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
import org.example.crypto.ThresholdCryptoConfig
import org.example.crypto.ThresholdDecryptionResult
import java.security.SecureRandom
import java.security.Security

class Server {
    private val logger = LogManager.getLogger(Server::class.java)
    private val secureRandom = SecureRandom.getInstanceStrong()

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
            bulletinboard.sendResults()

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
            val thresholdResults : MutableList<ThresholdDecryptionResult> = mutableListOf()

            for(vote in votes) {
                val thresholdResult = ThresholdCryptoConfig.thresholdDecrypt(vote.getEncryptedMessage(), decryptionServers)
                thresholdResults.add(thresholdResult)
                logger.info("decrypted vote ${thresholdResult.message}")
            }

            // TODO: run verifier on everyting, send the result of the verifier

            logger.info("Running verifier...")

            val verifier = Verifier()

            // test1: Computes the SHA-256 hash of the Bulletin Board's public key.
            val BBKeyHash = verifier.test1_GenerateBBKeyHash(config.publicKey)

            // test2: Verifies that the Bulletin Board's general parameters block is authentic.
            // val test2Result = verifier.test2_VerifyBBParametersSignature(bulletinboard.getParametersData(), bulletinboard.getSignature(), config.publicKey)

            // test3: Verifies that each mix batch output is produced by an authorized mix server.
            val test3Result = verifier.test3_VerifyMixersAuthorization(serversManager.getAllPublicKeys() ,bulletinboard.getMixBatchOutputs(startMix.pollId))

            // test4: Verifies that the signed encrypted vote list is authentic.
            val test4Result = verifier.test4_VerifyEncryptedVoteListSignature(bulletinboard.getVoteListData(), bulletinboard.getVoteListSignature(), bulletinboard.getPublicKey())

            // test5: Verifies that each mix batch output is correctly signed.
            val test5Result = verifier.test5_VerifyMixBatchOutputSignature(serversManager.getMixBatchOutputs(), config.mixServersPublicKeys)

            // test6: Verifies that the first mixer's input equals the signed encrypted vote list.
            val test6Result = verifier.test6_VerifyFirstMixerInput(serversManager.getMixBatchOutputs(), bulletinboard.getVoteListData())

            // test7: Verifies the mixing chain consistency across all mix batches.
            val test7Result = verifier.test7_VerifyMixingChain(bulletinboard.getMixBatchOutputs(pollID))

            // test8: Verifies the Zero-Knowledge Proofs (ZKPs) of the mixing process.
            val test8Result = verifier.test8_VerifyMixersZKP(serversManager.getMixBatchOutputs(), domainParameters, publicKey)

            // test9: Verifies the Zero-Knowledge Proofs for the decryption process.
            val test9Result = verifier.test9_VerifyDecryptionZKP()

            // test10: Summarizes the final decrypted votes.
            val test10Result = verifier.test10_SummarizeDecryptedVotes(thresholdResults)



            val results = thresholdResults.map { it.message }.groupingBy { it }.eachCount()

            // TODO: send results - only if verifier is ok
        }

    }
}