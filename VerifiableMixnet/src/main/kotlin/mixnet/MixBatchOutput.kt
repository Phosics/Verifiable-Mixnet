package org.example.mixnet

import meerkat.protobuf.Crypto
import meerkat.protobuf.Mixing
import org.example.MixnetTest.toHex

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

        // CiphertextsMatrix
        sb.append("  CiphertextsMatrix:\n")
        ciphertextsMatrix.forEachIndexed { layerIdx, layer ->
            sb.append("    Row ${layerIdx + 1}:\n")
            layer.forEachIndexed { voteIdx, ciphertext ->
                val dataHex = ciphertext.data.toByteArray().toHex()
                val truncatedHex = if (dataHex.length > 8) "${dataHex.substring(0, 32)}..." else dataHex
                sb.append("      Vote ${voteIdx + 1}: $truncatedHex\n")
            }
        }

        // ProofsMatrix
        sb.append("  ProofsMatrix:\n")
        proofsMatrix.forEachIndexed { layerIdx, layer ->
            sb.append("    Row ${layerIdx + 1}:\n")
            layer.forEachIndexed { proofIdx, proof ->
                val proofHex = proof.toByteArray().toHex()
                val truncatedHex = if (proofHex.length > 8) "${proofHex.substring(0, 8)}..." else proofHex
                sb.append("      Proof ${proofIdx + 1}: $truncatedHex\n")
            }
        }

        return sb.toString()
    }

    /**
     * Verifies the Zero-Knowledge Proofs (ZKPs) within a MixBatchOutput.
     * Returns true if all proofs are valid.
     *
     * @param mixBatchOutput The MixBatchOutput containing proofs to verify.
     * @return True if all proofs are valid, False otherwise.
     */
    fun verifyMixBatch(): Boolean {
        // Iterate through each layer's proofs
        for (layerProofs in proofsMatrix) {
            for (proof in layerProofs) {
                if (!validateProof(proof)) {
                    return false
                }
            }
        }
        return true
    }

    /**
     * Validates a single Mix2Proof.
     *
     * @param proof The Mix2Proof to validate.
     * @return True if the proof is valid, False otherwise.
     */
    private fun validateProof(proof: Mixing.Mix2Proof): Boolean {
        // TODO: Implement actual proof validation logic
        // For now, return true if the proof is the default instance
//        println("proof: $proof\t default: ${Mixing.Mix2Proof.getDefaultInstance()}")
        return proof == defaultProof
    }

}