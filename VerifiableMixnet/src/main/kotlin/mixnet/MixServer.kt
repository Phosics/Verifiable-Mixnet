package mixnet

import bulltinboard.BulletinBoard
import bulltinboard.TIMEOUT
import kotlinx.coroutines.delay
import meerkat.protobuf.Mixing
import org.apache.logging.log4j.LogManager
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.example.mixnet.*
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*

/**
 * MixServer implements Abe's Permutation-network-based mix.
 * It serializes the output as per the specified on-disk format.
 */
class MixServer(
    publicKey: PublicKey,
    domainParameters: ECDomainParameters,
    private val index: Int) {
    private val bulletinBoard : BulletinBoard = BulletinBoard()
    private val n : Int = bulletinBoard.numberOfVotes

    /**
     * Creation:
     * Inputs:
     * 1.   Amount of votes to be mixed (should be 2^n)
     * 2.   Create a matrix of Switch objects: columns - 2 * log(n)_2 - 1, rows - n / 2
     * 3.   Create a random permutation of the n votes
     * 4.   Run the algorithm of the shuffle to fix the switches
     */
    private val random = SecureRandom.getInstanceStrong()
    private val permutationNetwork : PermutationNetwork
    private val logger = LogManager.getLogger(MixServer::class.java)

    init {
        require(n > 0 && (n and (n - 1)) == 0) {
            "n must be a power of 2."
        }
        validatePublicKey(publicKey)
        permutationNetwork = PermutationNetwork(publicKey, domainParameters, n, random)
    }

    fun getIndex() : Int {
        return index
    }

    suspend fun run() {
        logger.info("Configuring...")
        configureRandomly()

        logger.info("Sleeping for ${(index + 1) * TIMEOUT} ms...")
        delay(((index + 1) * TIMEOUT).toLong())
        logger.info("Server ${index + 1} Waking up...")

        val (mixedVotes, ciphertextsMatrix, proofsMatrix) = permutationNetwork.apply(getVotes())

        bulletinBoard.sendMixBatchOutput(createMixBatchOutput(ciphertextsMatrix, proofsMatrix))

        logger.info("Published votes and proofs.")
    }

    private fun getVotes(): List<Vote> {
        logger.info("Getting the starting votes...")
        var currentVotes = bulletinBoard.votes
        val mixBatches = bulletinBoard.getMixBatchOutputs()

        for (mixBatch in mixBatches) {
            logger.info("Verifying the votes published in mixBatch ${mixBatch.header}...")

            // TODO: verify mixbatch
            currentVotes = mixBatch.getVotes()
        }

        return currentVotes
    }

    private fun validatePublicKey(key: PublicKey) {
        require(key is ECPublicKey) { "Invalid public key type" }
        require(key.parameters.curve.fieldSize >= 256) {
            "Insufficient key size"
        }
    }

    /**
     * Randomly choose a permutation sigma of {0,1,...,n-1}, Using Fisher-Yates Algorithm.
     * This algorithm ensures that every possible permutation is equally likely.
     *
     * NOTE: This σ is 0-based, meaning σ[i]=some j in [0..n-1].
     *
     */
    private fun randomPermutation(n: Int): IntArray {
        val perm = IntArray(n) { it }    // [0,1,2,...,n-1]
        for (i in (n-1) downTo 1) {
            val j = random.nextInt(i + 1)
            // swap perm[i] and perm[j]
            val tmp = perm[i]
            perm[i] = perm[j]
            perm[j] = tmp
        }
        return perm
    }

    /**
     * Configures the network with a random permutation.
     */
    private fun configureRandomly() {
        val sigma = randomPermutation(n)
        permutationNetwork.configNetBySigma(sigma)
    }

    private fun createMixBatchOutput(ciphertextsMatrix : List<List<Vote>>, proofsMatrix : List<List<Mixing.Mix2Proof>>): MixBatchOutput {
        // Create MixBatchHeader
        val header = Mixing.MixBatchHeader.newBuilder()
            .setLogN((Math.log(n.toDouble()) / Math.log(2.0)).toInt())
            .setLayers((2 * (Math.log(n.toDouble()) / Math.log(2.0)) - 1).toInt()) // 2 * (log_2(N)) -1
            .build()

        // Populate MixBatchOutput
        return MixBatchOutput(
            header = header,
            ciphertextsMatrix = ciphertextsMatrix.map { layerVotes ->
                layerVotes.map { it.getEncryptedMessage() }
            },
            proofsMatrix = proofsMatrix
        )
    }
}
