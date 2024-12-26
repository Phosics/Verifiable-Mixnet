package mixnet

import org.example.mixnet.Switch

class PermutationNetwork(n: Int) {
    private var switch: Switch? = null
    private var firstCol: List<Switch>? = null
    private var lastCol: List<Switch>? = null
    private var top: PermutationNetwork? = null
    private var bottom: PermutationNetwork? = null

    init {
        if (n > 2) {
            top = PermutationNetwork(n / 2)
            bottom = PermutationNetwork(n / 2)
            firstCol = List(n / 2) { index ->
                Switch()
            }
            lastCol = List(n / 2) { index ->
                Switch()
            }
        } else {
            switch = Switch()
        }
    }
}