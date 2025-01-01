package mixnet

import org.example.mixnet.Switch

class PermutationNetwork(val n: Int) {
    private var switch: Switch? = null
    private var firstCol: MutableList<Switch>? = null
    private var lastCol: MutableList<Switch>? = null
    private var top: PermutationNetwork? = null
    private var bottom: PermutationNetwork? = null

    init {
        require(n > 0 && (n and (n - 1)) == 0) { "n must be a power of 2." }

        if (n > 2) {
            top = PermutationNetwork(n / 2)
            bottom = PermutationNetwork(n / 2)
            firstCol = MutableList(n / 2) { Switch() }
            lastCol = MutableList(n / 2) { Switch() }
        } else {
            // If n=2, we only have one switch
            switch = Switch()
        }
    }

    /**
     * Applies the entire permutation network to an immutable list of votes (size must be n).
     * Returns a new list of votes.
     */
    fun apply(votes: List<Vote>): List<Vote> {
        if(n == 2) {
            // Base case: single switch
            return switch!!.apply(votes)
        }

        // 1. Apply first column
        val firstColResult = applyCol(votes, firstCol!!)

        // 2. Re-map wires for sub-networks
        val firstColMapped = applyFirstColMap(firstColResult)

        // 3. Recurse on top half and bottom half
        val half = n / 2
        val topInput = firstColMapped.subList(0, half)   // safe to read: creates a view
        val bottomInput = firstColMapped.subList(half, n)

        // Because subList returns a view, we create new lists if we want pure immutability:
        val topResult = top!!.apply(topInput.toList())
        val bottomResult = bottom!!.apply(bottomInput.toList())

        // 4. Combine
        val combined = topResult + bottomResult

        // 5. Re-map wires after sub-networks
        val lastMapRes = applyLastColMap(combined)

        // 6. Apply last column
        val lastColResult = applyCol(lastMapRes, lastCol!!)

        return lastColResult
    }

    private fun applyCol(votes: List<Vote>, col: List<Switch>): List<Vote> {
        val result = mutableListOf<Vote>()
        for (i in col.indices) {
            // Instead of subList, explicitly pick two votes
            val subVotes = listOf(votes[2*i], votes[2*i + 1])

            // Apply the switch
            val applied = col[i].apply(subVotes)
            // Append them
            result.addAll(applied)
        }
        return result
    }


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
    fun configNetBySigma(sigma: IntArray) {
        require(sigma.size == n) { "Permutation size must match n=$n" }
        require(isValidPermutation(sigma)) { "sigma must be a valid permutation." }

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
        while (true) {
            // Step 1: Find the smallest unset i
            val i = F.indexOfFirst { !it }
            if (i == -1) break // All flags are set

            // Step 1: If i is the first index, set the corresponding last column switch arbitrarily
            if (i == 0) {
                lastCol[0].setB(0)
            }

            var currentI = i
            while (true) {
                // Step 2-1: Mark F[currentI]
                F[currentI] = true

                // Step 2-2: Identify j such that ˜I_j = O_i
                // j is the input index connected to O_i via the last column switch.
                var switchIndex = currentI / 2

                val j = if (lastCol[switchIndex].getB() == 0) {
                    currentI
                } else {
                    partnerWire(currentI)
                }

                // Step 2-3: Let k = sigma[i]
                val k = sigma[currentI]
                if (oneEvenOneOdd(j, k)) {
                    firstCol[k / 2].setB(1)
                }

                // Step 2-4: Identify l such that ˜O_l = I_k
                val kBar = partnerWire(k)
                switchIndex = kBar / 2

                val l = if (firstCol[switchIndex].getB() == 0) {
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
                    lastCol[t / 2].setB(1)
                }

                // Step 2-6: Mark F[t] and set currentI to partnerWire(t)
                F[t] = true
                val tBar = partnerWire(t)

                // Step 2-7: If F[tBar] is already set, exit the inner loop
                if (F[tBar]) break

                currentI = tBar
            }
        }

        // Step 4: Recursively configure the top and bottom sub-networks
        // Built by constructing O and I arrays from first and last column switches

        // Step 4.1: Build the OBar array based on the first column switches
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

        // Step 4.2: Apply mapping to OBar
        val OBarMapped = applyOBarMap(OBar)

        // Step 4.3: Build the IBar array based on the last column switches
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

        for (j in 0 until n) {
            IBar[j] = sigma[IBar[j]]
        }

        // Step 4.4: Apply mapping to IBar
        val IBarMapped = applyIBarMap(IBar)

        // Step 4.5: Initialize top and bottom permutation arrays
        val topPermutation = IntArray(n / 2)
        val bottomPermutation = IntArray(n / 2)

        // Step 4.6: Assign to topPermutation and bottomPermutation based on OBarMapped and IBarMapped
        for (j in 0 until n) {
            val I_j = IBarMapped[j] // IBarMapped[j] is the input connected via the last column

            // Find i such that OBarMapped[i] == I_j
            val O_j = OBarMapped.indexOf(I_j)
            if (O_j == -1) {
                throw IllegalArgumentException("No corresponding OBarMapped[i] found for IBarMapped[j] = $I_j")
            }

            // Assign to topPermutation or bottomPermutation based on i
            if (j < n / 2) {
                // Assign to topPermutation
                topPermutation[j] = O_j
            } else {
                // Assign to bottomPermutation
                bottomPermutation[j - (n/2)] = O_j - (n/2)
            }
        }

        // Step 4.7: Debugging: Print the top and bottom permutations
        println("Top Permutation: ${topPermutation.toList()}")
        println("Bottom Permutation: ${bottomPermutation.toList()}")

        // Step 4.8: Validate that topPermutation and bottomPermutation are valid permutations
        require(isValidSubPermutation(topPermutation)) { "Top permutation is invalid: ${topPermutation.toList()}" }
        require(isValidSubPermutation(bottomPermutation)) { "Bottom permutation is invalid: ${bottomPermutation.toList()}" }

        // Step 4.9: Recursively configure the sub-networks
        top!!.configNetBySigma(topPermutation)
        bottom!!.configNetBySigma(bottomPermutation)
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
     * Partner wire means if i is even => i+1, if i is odd => i-1.
     * Ensures that the partner wire stays within bounds.
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
        if (sigma.size!=2) error("Base case invoked with n!=2")
        val sw = switch ?: error("switch==null in baseCase")

        val (s0, s1) = sigma
        if (s0==0 && s1==1) {
            sw.setB(0)
        } else if (s0==1 && s1==0) {
            sw.setB(1)
        } else {
            throw IllegalArgumentException("Invalid sigma for n=2: ${sigma.toList()}")
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