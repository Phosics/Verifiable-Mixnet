package org.example.mixnet

data class SwitchPost (
    private val votes : List<Vote>,
    private val mixBatchOutput: MixBatchOutput) {

    fun getVotes(): List<Vote> {
        return votes
    }

    fun getMixBatchOutput(): MixBatchOutput {
        return mixBatchOutput
    }
}