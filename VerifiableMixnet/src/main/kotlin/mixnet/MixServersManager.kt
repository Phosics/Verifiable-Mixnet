package mixnet

import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.Vote
import java.security.PublicKey

/**
 * Manages multiple MixServer instances to imitate a mixnet.
 *
 * @param t The number of adversaries. The total number of servers is 2t + 1.
 * @param n The number of votes to be mixed. Must be a power of 2.
 */
class MixServersManager(
    private val publicKey: PublicKey,
    private val domainParameters: ECDomainParameters,
    private val t: Int,
    private val n: Int
) {
    private val numServers = 2 * t + 1

    private val mixServers: List<MixServer>

    init {
        require(t > 0) { "Number of adversaries t must be positive" }
        require(n > 0 && (n and (n - 1)) == 0) { "n must be a power of 2" }

        // Initialize 2t + 1 MixServer instances
        mixServers = List(numServers) { index ->
            println("Initializing MixServer ${index + 1}/$numServers with n=$n")
            MixServer(publicKey, domainParameters, n)
        }
    }

    /**
     * Applies the mixnet to the given votes by passing them through each MixServer in sequence.
     *
     * @param votes The list of votes to be mixed. Size must be exactly n.
     * @return A list of MixBatchOutput from each server.
     */
    fun processMixBatch(votes: List<Vote>): List<MixBatchOutput> {
        require(votes.size == n) {
            "processMixBatch() requires exactly n=$n votes, but got ${votes.size}"
        }

        var currentVotes = votes
        val mixBatchOutputs = mutableListOf<MixBatchOutput>()

        mixServers.forEachIndexed { index, server ->
            server.configureRandomly()
            println("Processing MixServer ${index + 1}/$numServers")
            val mixBatchOutput = server.processMixBatch(currentVotes)
            mixBatchOutputs.add(mixBatchOutput)
            println("Completed MixServer ${index + 1}/$numServers")

            // Update currentVotes with the mixed votes from the last column
            currentVotes = mixBatchOutput.ciphertextsMatrix.map { Vote(it.last()) }
        }

        return mixBatchOutputs
    }
}