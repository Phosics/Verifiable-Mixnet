package org.example.mixnet

import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.io.OutputStream


/**
 * Encapsulates the serialized output of a mix batch.
 */

data class MixBatchOutput(
    val header: Mixing.MixBatchHeader,
    val ciphertextsMatrix: List<List<RerandomizableEncryptedMessage>>,
    val proofsMatrix: List<List<Mixing.Mix2Proof>>,
    val ed25519PublicKey : Ed25519PublicKeyParameters
) {
    private lateinit var signatureEd25519: ByteArray

    fun getSignature() : ByteArray {
        return signatureEd25519
    }

    fun setSignature(bytes: ByteArray) {
        signatureEd25519 = bytes
    }

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

        // Display the Ed25519 signature (if present)
        if (signatureEd25519 != null) {
            val sigHex = signatureEd25519.joinToString("") { "%02x".format(it) }
            sb.append("  Ed25519 Signature: $sigHex\n")
        }

        // Display the Ed25519 public key (if present)
        if (ed25519PublicKey != null) {
            val pubKeyHex = ed25519PublicKey.encoded.joinToString("") { "%02x".format(it) }
            sb.append("  Ed25519 Public: $pubKeyHex\n")
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

    fun getVotes() : List<Vote> {
        return ciphertextsMatrix.map { it.last() }.map { Vote(it) }
    }
}