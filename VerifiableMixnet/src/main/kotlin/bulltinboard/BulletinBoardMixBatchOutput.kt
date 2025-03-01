package bulltinboard

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.Mixing.Mix2Proof
import meerkat.protobuf.Mixing.MixBatchHeader
import org.example.mixnet.MixBatchOutput
import java.util.*
import java.util.Base64.Decoder

@Serializable
data class BulletinBoardMixBatchOutput(
    val header : String,
    val ciphertextsMatrix : List<List<String>>,
    val proofsMatrix : List<List<String>>) {

    fun extract(): MixBatchOutput {
        val decoder = Base64.getDecoder()
        val header = decodeHeader(decoder)
        val ciphertextsMatrix = decodeCiphertextsMatrix(decoder)
        val proofsMatrix = decodeProofsMatrix(decoder)

        return MixBatchOutput(header, ciphertextsMatrix, proofsMatrix)
    }

    private fun decodeProofsMatrix(decoder: Decoder) : List<List<Mix2Proof>> {
        val result : MutableList<List<Mix2Proof>> = mutableListOf()

        for (row in proofsMatrix) {
            val colResult : MutableList<Mix2Proof> = mutableListOf()

            for (cell in row) {
                colResult.add(Mix2Proof.parseFrom(decoder.decode(cell)))
            }

            result.add(colResult)
        }

        return result
    }

    private fun decodeCiphertextsMatrix(decoder: Decoder) : List<List<RerandomizableEncryptedMessage>> {
        val result : MutableList<List<RerandomizableEncryptedMessage>> = mutableListOf()

        for (row in ciphertextsMatrix) {
            val colResult : MutableList<RerandomizableEncryptedMessage> = mutableListOf()

            for (cell in row) {
                colResult.add(RerandomizableEncryptedMessage.parseFrom(decoder.decode(cell)))
            }

            result.add(colResult)
        }

        return result
    }

    private fun decodeHeader(decoder : Decoder): MixBatchHeader {
        return MixBatchHeader.parseFrom(decoder.decode(header))
    }
}

@Serializable
data class BulletinBoardMixBatchOutputRecord(
    @SerialName("_id")
    val id : String,
    @SerialName("mixBatch")
    val mixBatchOutput: BulletinBoardMixBatchOutput,
    @SerialName("timestamp")
    val timestamp: String,
    @SerialName("signature")
    val signature: String
)

@Serializable
data class BulletinBoardMixBatchOutputs(
    val mixBatches : List<BulletinBoardMixBatchOutputRecord>
) {
    fun extract() : List<MixBatchOutput> {
        val result : MutableList<MixBatchOutput> = mutableListOf()

        for (mixBatch in mixBatches) {
            result.add(mixBatch.mixBatchOutput.extract())
        }

        return result
    }
}