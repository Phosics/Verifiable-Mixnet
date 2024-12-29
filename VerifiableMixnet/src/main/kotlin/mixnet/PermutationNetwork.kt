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
            switch = Switch()
        }
    }

    private fun applyFirstColMap(votes: MutableList<Vote>): List<Vote> {
        val result: MutableList<Vote> = MutableList(votes.size) { votes[it] } // Initialize with same size

        // Iterate over the first half of the input list
        for (i in 0 until votes.size / 2) {
            result[i] = votes[2 * i]                  // Add even-indexed element
            result[i + votes.size / 2] = votes[2 * i + 1] // Add odd-indexed element
        }

        return result
    }

    private fun applyLastColMap(votes: MutableList<Vote>): MutableList<Vote> {
        val result: MutableList<Vote> = MutableList(votes.size) { votes[it] } // Initialize with same size

        for (i in 0 until votes.size / 2) {
            result[2 * i] = votes[i]                  // Map first half to even indices
            result[2 * i + 1] = votes[i + votes.size / 2] // Map second half to odd indices
        }

        return result
    }

    private fun applyCol(votes: MutableList<Vote>, col: MutableList<Switch>): MutableList<Vote> {
        val result: MutableList<Vote> = mutableListOf()

        for (i in col.indices) {
            val subVotes = votes.subList(2 * i, 2 * i + 2)
            val appliedVote = col[i].apply(subVotes)
            result.addAll(appliedVote)
        }

        return result
    }

    fun apply(votes: MutableList<Vote>) : MutableList<Vote>? {
        if(n == 2) {
            return switch?.apply(votes)
        }

        val firstColRes = firstCol?.let { applyCol(votes, it) }
            ?: throw IllegalStateException("First column application failed.")

        val firstColMappedVotes = applyFirstColMap(firstColRes).toMutableList()

        val topRes = top?.apply(firstColMappedVotes.subList(0, n / 2))
            ?: throw IllegalStateException("Top network application failed.")
        val bottomRes = bottom?.apply(firstColMappedVotes.subList(n / 2, n))
            ?: throw IllegalStateException("Bottom network application failed.")

        val combinedVotes = topRes + bottomRes

        val lastMapRes = applyLastColMap(combinedVotes.toMutableList())

        val lastColRes = lastCol?.let { applyCol(lastMapRes, it) }
            ?: throw IllegalStateException("Last column application failed.")

        return lastColRes
    }

}