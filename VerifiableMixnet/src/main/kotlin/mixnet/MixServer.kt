package mixnet

class MixServer(n: Int) {
    /**
     * Creation:
     * Inputs:
     * 1.   Amount of votes to be mixed (should be 2^n)
     * 2.   Create a matrix of Switch objects: columns - 2 * log(n)_2 - 1, rows - n / 2
     * 3.   Create a random permutation of the n votes
     * 4.   Run the algorithm of the shuffle to fix the switches
     */
    private val permutationNetwork = PermutationNetwork(n)

    init {

    }

    /**
     * Running:
     */
}
