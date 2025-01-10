package org.example.mixnet

import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.Mixing.MixBatchHeader
import meerkat.protobuf.Mixing.Mix2Proof
import java.io.OutputStream

object MixerUtils {

    /**
     * Writes the MixBatchHeader to the OutputStream using writeDelimitedTo().
     */
    fun writeMixBatchHeader(header: MixBatchHeader, outputStream: OutputStream) {
        header.writeDelimitedTo(outputStream)
    }

    /**
     * Writes a list of RerandomizableEncryptedMessages to the OutputStream using writeDelimitedTo().
     */
    fun writeCiphertexts(ciphertexts: List<RerandomizableEncryptedMessage>, outputStream: OutputStream) {
        ciphertexts.forEach { ciphertext ->
            ciphertext.writeDelimitedTo(outputStream)
        }
    }

    /**
     * Writes a list of Mix2Proofs to the OutputStream using writeDelimitedTo().
     */
    fun writeProofs(proofs: List<Mix2Proof>, outputStream: OutputStream) {
        proofs.forEach { proof ->
            proof.writeDelimitedTo(outputStream)
        }
    }
}