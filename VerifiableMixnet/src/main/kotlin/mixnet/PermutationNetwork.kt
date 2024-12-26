package mixnet

import org.example.mixnet.Switch

class PermutationNetwork(val n: Int) {
    private var switch: Switch? = null
    private var firstCol: MutableList<Switch>? = null
    private var lastCol: MutableList<Switch>? = null
    private var top: PermutationNetwork? = null
    private var bottom: PermutationNetwork? = null

    init {
        if (n > 2) {
            top = PermutationNetwork(n / 2)
            bottom = PermutationNetwork(n / 2)
            firstCol = MutableList(n / 2) { index ->
                Switch()
            }
            lastCol = MutableList(n / 2) { index ->
                Switch()
            }
        } else {
            switch = Switch()
        }
    }

    fun applyMap(votes: MutableList<Vote>): MutableList<Vote> {
        val result: MutableList<Vote> = mutableListOf()

        for (i in 0 until votes.size / 2) {
            result.add(i, votes[2 * i])
            result.add(i + votes.size / 2, votes[2 * i + 1])
        }

        return result
    }

    fun applyCol(votes: MutableList<Vote>, col: MutableList<Switch>): MutableList<Vote> {
        val result: MutableList<Vote> = mutableListOf()

        for (i in 0 until col.size) {
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

        // TODO: add switching map

        if(firstColRes == null) {
            // TODO: Handle error
            return null
        }

        val topRes = top?.apply(firstColRes.subList(0, n / 2))
        val bottomRes = bottom?.apply(firstColRes.subList(n / 2, n))

        if(topRes == null || bottomRes == null) {
            // TODO: Handle error
            return null
        }

        topRes.addAll(bottomRes)

        // TODO: add switching map

        return lastCol?.let { applyCol(topRes, it) }
    }
}