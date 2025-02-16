package bulltinboard

import kotlinx.serialization.Serializable

@Serializable
data class BulletinBoardMixBatchOutput(
    val header : String,
    val ciphertextsMatrix : List<List<String>>,
    val proofsMatrix : List<List<String>>
)

@Serializable
data class BulletinBoardMixBatchOutputs(
    val mixBatches : List<BulletinBoardMixBatchOutput>
)