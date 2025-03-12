package mixnet

import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters


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

        return sb.toString()
    }



    /**
     * Extension function to convert ByteArray to hex string.
     */
    fun ByteArray.toHex(): String {
        return org.bouncycastle.util.encoders.Hex.toHexString(this)
    }

    /**
     * getter for the votes
     */
    fun getVotes() : List<Vote> {
        return ciphertextsMatrix.map { it.last() }.map { Vote(it) }
    }
}