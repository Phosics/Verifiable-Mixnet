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

            val results = thresholdResults.map { it.message }.groupingBy { it }.eachCount()

            // TODO: send results - only if verifier is ok
        }

    }
}