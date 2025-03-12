package mixnet

import bulltinboard.BulletinBoard
import org.apache.logging.log4j.LogManager
import org.bouncycastle.asn1.x9.DomainParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoConfig
import org.example.crypto.CryptoUtils
import org.example.mixnet.MixBatchOutputVerifier
import org.example.mixnet.Vote
import java.security.PublicKey

class VotesReceiver {
    private val logger = LogManager.getLogger(VotesReceiver::class.java)

    fun getVotes(bulletinBoard: BulletinBoard, publicKey: PublicKey, domainParameters: ECDomainParameters, pollID: String): List<Vote> {
        logger.info("Getting the starting votes...")
        var currentVotes = bulletinBoard.votes
        val mixBatches = bulletinBoard.getMixBatchOutputs(pollID)

        for (mixBatch in mixBatches) {
            logger.info("Verifying MixBatchOutput ${mixBatch.key}...")

            if (!MixBatchOutputVerifier(domainParameters, publicKey).verifyMixBatchOutput(mixBatch.value)) {
                logger.info("Verification failed for MixBatchOutput ${mixBatch.key}, skipping...")
                continue
            }

            currentVotes = mixBatch.value.getVotes()
        }

        return currentVotes
    }

}