package mixnet

import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.Vote
import java.security.PublicKey
import java.util.*

/**
 * MixServer implements Abe's Permutation-network-based mix.
 * It serializes the output as per the specified on-disk format.
 */
class MixServer(
    private val publicKey: PublicKey,
    private val domainParameters: ECDomainParameters,
    private val n: Int
) {
    /**
     * Creation:
     * Inputs:
     * 1.   Amount of votes to be mixed (should be 2^n)
     * 2.   Create a matrix of Switch objects: columns - 2 * log(n)_2 - 1, rows - n / 2
     * 3.   Create a random permutation of the n votes
     * 4.   Run the algorithm of the shuffle to fix the switches
     */
    private val permutationNetwork = PermutationNetwork(publicKey, domainParameters, n)
    private val random = Random()


    init {
        require(n > 0 && (n and (n - 1)) == 0) {
            "n must be a power of 2."
        }
        validatePublicKey(publicKey)
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
    fun configureRandomly() {
        val sigma = randomPermutation(n)
        permutationNetwork.configNetBySigma(sigma)
    }

    /**
     * Applies the mix to the given votes.
     *
     * @param votes A list of n Vote instances.
     * @return A Triple containing mixed votes, ciphertexts matrix, and proofs matrix.
     */
    fun apply(votes: List<Vote>): Triple<List<Vote>, List<List<Vote>>, List<List<Mixing.Mix2Proof>>> {
        return permutationNetwork.apply(votes)
    }


    /**
     * Processes a mix batch and returns the serialized components as a MixBatchOutput object.
     *
     * @param votes The list of votes to be mixed.
     * @return A MixBatchOutput containing the header, ciphertexts matrix, and proofs matrix.
     */
    fun processMixBatch(votes: List<Vote>): MixBatchOutput {
        // 1. Apply the mix
        val (mixedVotes, ciphertextsMatrix, proofsMatrix) = apply(votes)

        // 2. Create MixBatchHeader
        val header = Mixing.MixBatchHeader.newBuilder()
            .setLogN((Math.log(n.toDouble()) / Math.log(2.0)).toInt())
            .setLayers((Math.log(n.toDouble()) / Math.log(2.0)).toInt())
            .build()

        // 3. Populate MixBatchOutput
        return MixBatchOutput(
            header = header,
            ciphertextsMatrix = ciphertextsMatrix.map { layerVotes ->
                layerVotes.map { it.getEncryptedMessage() }
            },
            proofsMatrix = proofsMatrix
        )
    }

}
