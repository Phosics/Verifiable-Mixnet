package mixnet

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.example.mixnet.Vote
import java.security.PublicKey
import java.util.*

class MixServer(private val publicKey: PublicKey, private val domainParameters: ECDomainParameters, private val n: Int) {
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
     * Public method: chooses a random permutation and configures the network accordingly.
     */
    fun configureRandomly() {
        var sigma = randomPermutation(n)
//        sigma = intArrayOf(2,0,3,1)
        // TODO: delete above
//        println("Sigma: ${sigma.contentToString()}")
        permutationNetwork.configNetBySigma(sigma)
    }

    /**
     * Once configured, apply the mix to the given votes (size = n).
     * Returns a new list of permuted/re-encrypted votes.
     */
    fun apply(votes: List<Vote>): List<Vote> {
        require(votes.size == n) {
            "apply() requires exactly n=$n votes, but got ${votes.size}"
        }
        return permutationNetwork.apply(votes)
    }

}
