package mixnet

import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.mixnet.Switch
import org.example.mixnet.Vote
import java.security.PublicKey


/**
 * PermutationNetwork manages a network of switches to perform permutations on votes.
 * It supports recursive configuration and collects proofs per layer.
 */
class PermutationNetwork(
    private val publicKey: PublicKey,
    private val domainParameters: ECDomainParameters,
    val n: Int
) {
    private var switch: Switch? = null
    private var firstCol: MutableList<Switch>? = null
    private var lastCol: MutableList<Switch>? = null
    private var top: PermutationNetwork? = null
    private var bottom: PermutationNetwork? = null

    init {
        require(n > 0 && (n and (n - 1)) == 0) { "n must be a power of 2." }

        if (n > 2) {
            initializeSubNetworks()
            initializeColumns()
        } else {
            // If n=2, we only have one switch
            switch = Switch(publicKey, domainParameters)
        }
    }

    /**
     * Initializes the top and bottom sub-networks.
     */
    private fun initializeSubNetworks() {
        top = PermutationNetwork(publicKey, domainParameters, n / 2)
        bottom = PermutationNetwork(publicKey, domainParameters, n / 2)
    }

    /**
     * Initializes the first and last column switches.
     */
    private fun initializeColumns() {
        firstCol = MutableList(n / 2) { Switch(publicKey, domainParameters) }
        lastCol = MutableList(n / 2) { Switch(publicKey, domainParameters) }
    }

    /**
     * Applies the entire permutation network to a list of votes (size must be n).
     * Collects ciphertexts and proofs in matrix formats.
     *
     * @param votes A list containing exactly n Vote instances.
     * @return A Triple containing mixed votes, ciphertexts matrix, and proofs matrix.
     */
    fun apply(votes: List<Vote>): Triple<List<Vote>, List<List<Vote>>, List<List<Mixing.Mix2Proof>>> {
        validateVotesSize(votes)

        return if (n == 2) {
            handleBaseCase(votes)
        } else {
            handleRecursiveCase(votes)
        }
    }

    private fun validateVotesSize(votes: List<Vote>) {
        require(votes.size == n) { "apply() requires exactly n=$n votes, but got ${votes.size}" }
    }

    private fun handleBaseCase(votes: List<Vote>): Triple<List<Vote>, List<List<Vote>>, List<List<Mixing.Mix2Proof>>> {
        // Initialize the ciphertextsMatrix with two rows, each containing one vote
        val ciphertextsMatrix = mutableListOf(
            mutableListOf(votes[0]),
            mutableListOf(votes[1])
        )

        // Apply the switch operation
        val switchedVotes = switch!!.apply(votes) // Should return exactly two votes

        // Append switchedVotes as the second column to ciphertextsMatrix
        ciphertextsMatrix[0].add(switchedVotes[0])
        ciphertextsMatrix[1].add(switchedVotes[1])

        // Initialize proofsMatrix with the switch proof for each row
        val proofsMatrix = mutableListOf(
            mutableListOf(switch!!.zkp!!)
        )

        // Return the result for the base case
        return Triple(switchedVotes, ciphertextsMatrix, proofsMatrix)
    }

    private fun handleRecursiveCase(votes: List<Vote>): Triple<List<Vote>, List<List<Vote>>, List<List<Mixing.Mix2Proof>>> {
        // Initialize the ciphertextsMatrix with n rows, each containing one vote (first column)
        val ciphertextsMatrix = votes.map { mutableListOf(it) }.toMutableList()

        // Apply the first column operation
        val firstColResult: List<Vote> = applyCol(votes, firstCol!!) // Should return exactly 'n' votes

        // Retrieve proofs from firstCol and add as the first column in proofsMatrix
        val firstColProofs: List<Mixing.Mix2Proof> = firstCol!!.map { it.zkp!! }
        val proofsMatrix = firstColProofs.map { mutableListOf(it) }.toMutableList()

        // Re-map wires for sub-networks
        val firstColMapped: List<Vote> = applyFirstColMap(firstColResult)

        // Recurse on top half and bottom half
        val half = n / 2
        val (topVotes, topCiphertexts, topProofs) = top!!.apply(firstColMapped.subList(0, half))
        val (bottomVotes, bottomCiphertexts, bottomProofs) = bottom!!.apply(firstColMapped.subList(half, n))

        // Combine results from sub-networks
        val combinedVotes = topVotes + bottomVotes
        val combinedCiphertexts = topCiphertexts + bottomCiphertexts
        val combinedProofs = topProofs + bottomProofs

        // Append combinedCiphertexts to ciphertextsMatrix
        combinedCiphertexts.forEachIndexed { index, ciphertexts ->
            ciphertextsMatrix[index].addAll(ciphertexts)
        }

        // Append combinedProofs to proofsMatrix
        combinedProofs.forEachIndexed { index, proofs ->
            proofsMatrix[index].addAll(proofs)
        }

        // Re-map wires after sub-networks
        val lastMapRes: List<Vote> = applyLastColMap(combinedVotes)

        // Apply last column operation
        val lastColResult: List<Vote> = applyCol(lastMapRes, lastCol!!) // Should return exactly 'n' votes

        // Retrieve proofs from lastCol and append as a new column
        val lastColProofs: List<Mixing.Mix2Proof> = lastCol!!.map { it.zkp!! }
        lastColProofs.forEachIndexed { index, proof ->
            proofsMatrix[index].add(proof)
        }

        // Append the lastColResult to ciphertextsMatrix as the final column
        lastColResult.forEachIndexed { index, vote ->
            ciphertextsMatrix[index].add(vote)
        }

        return Triple(lastColResult, ciphertextsMatrix, proofsMatrix)
    }

    /**
     * Applies a column of switches to the provided votes.
     */
    private fun applyCol(votes: List<Vote>, col: List<Switch>): List<Vote> {
        val result = mutableListOf<Vote>()
        for (i in col.indices) {
            // Explicitly pick two votes
            val subVotes = listOf(votes[2 * i], votes[2 * i + 1])

            // Apply the switch
            val applied = col[i].apply(subVotes)
            // Append the results
            result.addAll(applied)
        }
        return result
    }

    /**
     * Maps the first column's result to prepare inputs for sub-networks.
     */
    private fun applyFirstColMap(votes: List<Vote>): List<Vote> {
        val size = votes.size
        val half = size / 2
        val result = MutableList(size) { votes[it] }  // copy

        for (i in 0 until half) {
            result[i] = votes[2 * i]
            result[i + half] = votes[2 * i + 1]
        }
        return result.toList()
    }

    /**
     * Maps the last column's result to finalize the permutation.
     */
    private fun applyLastColMap(votes: List<Vote>): List<Vote> {
        // Reverse of applyFirstColMap
        val size = votes.size
        val half = size / 2
        val result = MutableList(size) { votes[it] }

        for (i in 0 until half) {
            result[2 * i] = votes[i]
            result[2 * i + 1] = votes[i + half]
        }
        return result.toList()
    }


    // ----------------------------------------------------------------
    //           WAKSMAN CONFIGURATION
    // ----------------------------------------------------------------

    /**
     * Configures this PermutationNetwork to realize the permutation sigma,
     * where sigma[i] = j means O_i = I_j (0-based).
     *
     * Implements the Waksman algorithm (Steps 1–3), then recurses on top/bottom.
     */
    fun configNetBySigma(sigma: IntArray){
        validateSigma(sigma)

        // Base case: n = 2 => single switch
        if (n == 2) {
            configBaseCase(sigma)
            return
        }

        // Ensure firstCol and lastCol are initialized
        val firstCol = firstCol ?: error("firstCol is null for n=$n > 2")
        val lastCol = lastCol ?: error("lastCol is null for n=$n > 2")

        // Initialize flags for outputs
        val F = BooleanArray(n) { false } // F[i] is true if O_i has been processed

        // Step 3: Repeat Step 1-2 until all flags are set
        configureSwitches(sigma, F)

        // Step 4: Recursively configure the top and bottom sub-networks
        configureSubNetworks(sigma, firstCol, lastCol)
    }

    /**
     * Validates the permutation sigma.
     */
    private fun validateSigma(sigma: IntArray) {
        require(sigma.size == n) { "Permutation size must match n=$n" }
        require(isValidPermutation(sigma)) { "sigma must be a valid permutation." }
    }

    /**
     * Configures the switches based on the Waksman algorithm steps.
     */
    private fun configureSwitches(sigma: IntArray, F: BooleanArray) {
        while (true) {
            // Step 1: Find the smallest unset i
            val i = F.indexOfFirst { !it }
            if (i == -1) break // All flags are set

            // Step 1: If i is the first index, set the corresponding last column switch arbitrarily
            if (i == 0) {
                lastCol!![0].setB(0)
            }

            var currentI = i
            while (true) {
                // Step 2-1: Mark F[currentI]
                F[currentI] = true

                // Step 2-2: Identify j such that ˜I_j = O_i
                // j is the input index connected to O_i via the last column switch.
                var switchIndex = currentI / 2

                val j = if (lastCol!![switchIndex].getB() == 0) {
                    currentI
                } else {
                    partnerWire(currentI)
                }

                // Step 2-3: Let k = sigma[i]
                val k = sigma[currentI]
                if (oneEvenOneOdd(j, k)) {
                    firstCol!![k / 2].setB(1)
                }

                // Step 2-4: Identify l such that ˜O_l = I_k
                val kBar = partnerWire(k)
                switchIndex = kBar / 2

                val l = if (firstCol!![switchIndex].getB() == 0) {
                    kBar
                } else {
                    partnerWire(kBar)
                }

                // Step 2-5: Find t such that sigma[t] = l
                val t = findInverse(sigma, kBar)
                if (t == -1) {
                    throw IllegalArgumentException("No t found such that sigma[t] = $l")
                }

                if (oneEvenOneOdd(t, l)) {
                    lastCol!![t / 2].setB(1)
                }

                // Step 2-6: Mark F[t] and set currentI to partnerWire(t)
                F[t] = true
                val tBar = partnerWire(t)

                // Step 2-7: If F[tBar] is already set, exit the inner loop
                if (F[tBar]) break

                currentI = tBar
            }
        }
    }

    /**
     * Configures the top and bottom sub-networks based on the configured switches.
     */
    private fun configureSubNetworks(sigma: IntArray, firstCol: MutableList<Switch>, lastCol: MutableList<Switch>) {
        // Step 4.1: Build the OBar array based on the first column switches
        val OBar = buildOBar(firstCol)

        // Step 4.2: Apply mapping to OBar
        val OBarMapped = applyOBarMap(OBar)

        // Step 4.3: Build the IBar array based on the last column switches
        val IBar = buildIBar(lastCol, sigma)

        // Step 4.4: Apply mapping to IBar
        val IBarMapped = applyIBarMap(IBar)

        // Step 4.5: Initialize top and bottom permutation arrays
        val (topPermutation, bottomPermutation) = assignSubPermutations(OBarMapped, IBarMapped)

        // Step 4.6: Debugging: Print the top and bottom permutations
        // println("Top Permutation: ${topPermutation.toList()}")
        // println("Bottom Permutation: ${bottomPermutation.toList()}")

        // Step 4.7: Validate that topPermutation and bottomPermutation are valid permutations
        require(isValidSubPermutation(topPermutation)) { "Top permutation is invalid: ${topPermutation.toList()}" }
        require(isValidSubPermutation(bottomPermutation)) { "Bottom permutation is invalid: ${bottomPermutation.toList()}" }

        // Step 4.8: Recursively configure the sub-networks
        top!!.configNetBySigma(topPermutation)
        bottom!!.configNetBySigma(bottomPermutation)
    }

    /**
     * Builds the OBar array based on the first column switches.
     */
    private fun buildOBar(firstCol: MutableList<Switch>): IntArray {
        val OBar = IntArray(n) { 0 }
        for (switchIndex in 0 until n / 2) {
            val bFirst = firstCol[switchIndex].getB()
            if (bFirst == 0) {
                // Switch is straight: OBar[2*s] = 2*s, OBar[2*s +1] = 2*s +1
                OBar[2 * switchIndex] = 2 * switchIndex
                OBar[2 * switchIndex + 1] = 2 * switchIndex + 1
            } else {
                // Switch is crossed: OBar[2*s] = 2*s +1, OBar[2*s +1] = 2*s
                OBar[2 * switchIndex] = 2 * switchIndex + 1
                OBar[2 * switchIndex + 1] = 2 * switchIndex
            }
        }
        return OBar
    }

    /**
     * Builds the IBar array based on the last column switches and the permutation sigma.
     */
    private fun buildIBar(lastCol: MutableList<Switch>, sigma: IntArray): IntArray {
        val IBar = IntArray(n) { 0 }
        for (switchIndex in 0 until n / 2) {
            val bLast = lastCol[switchIndex].getB()
            if (bLast == 0) {
                // Switch is straight: IBar[2*s] = 2*s, IBar[2*s +1] = 2*s +1
                IBar[2 * switchIndex] = 2 * switchIndex
                IBar[2 * switchIndex + 1] = 2 * switchIndex + 1
            } else {
                // Switch is crossed: IBar[2*s] = 2*s +1, IBar[2*s +1] = 2*s
                IBar[2 * switchIndex] = 2 * switchIndex + 1
                IBar[2 * switchIndex + 1] = 2 * switchIndex
            }
        }

        // Apply permutation sigma to IBar
        for (j in 0 until n) {
            IBar[j] = sigma[IBar[j]]
        }
        return IBar
    }

    /**
     * Assigns the top and bottom sub-permutations based on OBarMapped and IBarMapped.
     */
    private fun assignSubPermutations(OBarMapped: IntArray, IBarMapped: IntArray): Pair<IntArray, IntArray> {
        val topPermutation = IntArray(n / 2)
        val bottomPermutation = IntArray(n / 2)

        for (j in 0 until n) {
            val I_j = IBarMapped[j] // IBarMapped[j] is the input connected via the last column

            // Find i such that OBarMapped[i] == I_j
            val O_j = OBarMapped.indexOf(I_j)
            if (O_j == -1) {
                throw IllegalArgumentException("No corresponding OBarMapped[i] found for IBarMapped[j] = $I_j")
            }

            // Assign to topPermutation or bottomPermutation based on j
            if (j < n / 2) {
                // Assign to topPermutation
                topPermutation[j] = O_j
            } else {
                // Assign to bottomPermutation
                bottomPermutation[j - (n / 2)] = O_j - (n / 2)
            }
        }

        return Pair(topPermutation, bottomPermutation)
    }

    /**
     * Validates if the provided subSigma array is a valid permutation of [0, size-1].
     */
    private fun isValidSubPermutation(subSigma: IntArray): Boolean {
        val size = subSigma.size
        val seen = BooleanArray(size) { false }
        for (num in subSigma) {
            if (num < 0 || num >= size || seen[num]) return false
            seen[num] = true
        }
        return true
    }

    // ----------------------------------------------------------------
    // Helper functions for Waksman logic
    // ----------------------------------------------------------------

    /**
     * Identifies the partner wire.
     * If i is even, returns i + 1; if odd, returns i - 1.
     * Throws an exception if out of bounds.
     */
    private fun partnerWire(i: Int): Int {
        return when {
            i % 2 == 0 && i + 1 < n -> i + 1
            i % 2 == 1 && i - 1 >= 0 -> i - 1
            else -> throw IndexOutOfBoundsException("No partner wire for i=$i in n=$n")
        }
    }

    /**
     * Returns true if exactly one of a, b is even and the other is odd.
     */
    private fun oneEvenOneOdd(a: Int, b: Int): Boolean {
        return ((a % 2 == 0) && (b % 2 == 1)) || ((a % 2 == 1) && (b % 2 == 0))
    }

    /**
     * Finds t such that sigma[t] = value.
     * Returns -1 if not found.
     */
    private fun findInverse(sigma: IntArray, value: Int): Int {
        for (i in sigma.indices) {
            if (sigma[i] == value) return i
        }
        return -1
    }

    /**
     * Validates if the provided sigma array is a valid permutation.
     */
    private fun isValidPermutation(sigma: IntArray): Boolean {
        val seen = BooleanArray(n)
        for (num in sigma) {
            if (num < 0 || num >= n || seen[num]) return false
            seen[num] = true
        }
        return true
    }

    /**
     * Base case: n=2 => we have one switch; set b=0 if sigma=[0,1], b=1 if sigma=[1,0].
     */
    private fun configBaseCase(sigma: IntArray) {
        if (sigma.size != 2) error("Base case invoked with n!=2")
        val sw = switch ?: error("switch==null in baseCase")

        val (s0, s1) = sigma
        when {
            s0 == 0 && s1 == 1 -> sw.setB(0)
            s0 == 1 && s1 == 0 -> sw.setB(1)
            else -> throw IllegalArgumentException("Invalid sigma for n=2: ${sigma.toList()}")
        }
    }

    /**
     * Applies the first column mapping to the OBar array.
     * @param OBar The original OBar array.
     * @return The mapped OBar array.
     */
    private fun applyOBarMap(OBar: IntArray): IntArray {
        val size = OBar.size
        val half = size / 2
        val result = IntArray(size) { 0 }

        for (i in 0 until half) {
            result[i] = OBar[2 * i]
            result[i + half] = OBar[2 * i + 1]
        }

        return result
    }

    /**
     * Applies the last column mapping to the IBar array.
     * @param IBar The original IBar array.
     * @return The mapped IBar array.
     */
    private fun applyIBarMap(IBar: IntArray): IntArray {
        val size = IBar.size
        val half = size / 2
        val result = IntArray(size) { 0 }

        for (i in 0 until half) {
            result[i] = IBar[2 * i]
            result[i + half] = IBar[2 * i + 1]
        }

        return result
    }

}