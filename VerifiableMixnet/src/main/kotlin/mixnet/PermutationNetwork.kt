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

}