package org.example.mixnet

import meerkat.protobuf.Crypto
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.Mixing
import org.bouncycastle.util.encoders.Hex.toHexString
import java.io.OutputStream

/**
 * Encapsulates the serialized output of a mix batch.
 */

data class MixBatchOutput(
    val header: Mixing.MixBatchHeader,
    val ciphertextsMatrix: List<List<Crypto.RerandomizableEncryptedMessage>>,
    val proofsMatrix: List<List<Mixing.Mix2Proof>>,

    val defaultProof:  Mixing.Mix2Proof = Mixing.Mix2Proof.newBuilder()
        .setFirstMessage(Mixing.Mix2Proof.FirstMessage.getDefaultInstance())
        .setFinalMessage(Mixing.Mix2Proof.FinalMessage.getDefaultInstance())
        .setLocation(Mixing.Mix2Proof.Location.newBuilder()
            .setLayer(0)        // Example value; set appropriately
            .setSwitchIdx(0)    // Example value; set appropriately
            .setOut0(0)         // Example value; set appropriately
            .setOut1(1)         // Example value; set appropriately
            .build())
        .build()
) {
    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("MixBatchOutput:\n")

        // Header
        sb.append("  Header:\n")
        sb.append("    LogN: ${header.logN}\n")
        sb.append("    Layers: ${header.layers}\n")

        // CiphertextsMatrix - interpret outer list as columns
        sb.append("  CiphertextsMatrix (Columns):\n")

        // Number of columns
        val ciphertextColumnCount = ciphertextsMatrix.size
        // Assuming non-empty columns to get rowCount; handle empty safely if needed
        val ciphertextRowCount = if (ciphertextColumnCount > 0) ciphertextsMatrix[0].size else 0

        for (rowIdx in 0 until ciphertextRowCount) {
            sb.append("    Layer ${rowIdx + 1}:\n")
            for (colIdx in 0 until ciphertextColumnCount) {
                val ciphertext = ciphertextsMatrix[colIdx][rowIdx]
                val dataHex = ciphertext.data.toByteArray().toHex()
                val truncatedHex =
                    if (dataHex.length > 32) "${dataHex.substring(0, 16)}..." else dataHex
                sb.append("      Row ${colIdx + 1}: $truncatedHex\n")
            }
        }

        // ProofsMatrix - interpret outer list as columns
        sb.append("  ProofsMatrix (Columns):\n")

        val proofsColumnCount = proofsMatrix.size
        val proofsRowCount = if (proofsColumnCount > 0) proofsMatrix[0].size else 0

        for (rowIdx in 0 until proofsRowCount) {
            sb.append("    Layer ${rowIdx + 1}:\n")
            for (colIdx in 0 until proofsColumnCount) {
                val proof = proofsMatrix[colIdx][rowIdx]
                val proofHex = proof.toByteArray().toHex()
                val truncatedHex =
                    if (proofHex.length > 8) "${proofHex.substring(0, 16)}..." else proofHex
                sb.append("      Row ${colIdx + 1}: $truncatedHex\n")
            }
        }

        return sb.toString()
    }



    /**
     * Extension function to convert ByteArray to hex string.
     */
    fun ByteArray.toHex(): String {
        return org.bouncycastle.util.encoders.Hex.toHexString(this)
    }

    /**
     * Serializes the MixBatchOutput to the given OutputStream using writeDelimitedTo().
     */
    fun serialize(outputStream: OutputStream) {
        // Write MixBatchHeader
        MixerUtils.writeMixBatchHeader(header, outputStream)

        // Write Ciphertexts Matrix column by column
        ciphertextsMatrix.forEach { column ->
            column.forEach { ciphertext ->
                MixerUtils.writeCiphertexts(listOf(ciphertext), outputStream)
            }
        }

        // Write Proofs Matrix column by column
        proofsMatrix.forEach { column ->
            column.forEach { proof ->
                MixerUtils.writeProofs(listOf(proof), outputStream)
            }
        }
    }

}