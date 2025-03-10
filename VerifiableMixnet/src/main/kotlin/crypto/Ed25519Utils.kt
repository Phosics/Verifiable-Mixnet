import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.example.mixnet.MixBatchOutput

object Ed25519Utils {

    /**
     * Sign the MixBatchOutput using the provided Ed25519 private key.
     * The function returns a NEW MixBatchOutput object with signatureEd25519 set.
     */
    fun signMixBatchOutput(
        batch: MixBatchOutput,
        privateKey: Ed25519PrivateKeyParameters
    ): MixBatchOutput {
        // 1) Serialize "core data" for signing:
        //    We just gather the existing fields minus the signature field itself.
        val bytesToSign = createCanonicalBytes(batch)

        // 2) Create the signer
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(bytesToSign, 0, bytesToSign.size)

        // 3) Generate signature
        val signature = signer.generateSignature()

        // 4) Return a copy of batch with signature attached
        return batch.copy(signatureEd25519 = signature)
    }

    /**
     * Verify the MixBatchOutput's signature using the provided Ed25519 public key.
     */
    fun verifyMixBatchOutput(
        batch: MixBatchOutput,
        publicKey: Ed25519PublicKeyParameters
    ): Boolean {
        val sig = batch.signatureEd25519 ?: return false // No signature? fail

        // 1) Serialize "core data"
        val bytesToCheck = createCanonicalBytes(batch.copy(signatureEd25519 = null))

        // 2) Create verifier
        val verifier = Ed25519Signer()
        verifier.init(false, publicKey)
        verifier.update(bytesToCheck, 0, bytesToCheck.size)

        // 3) Verify signature
        return verifier.verifySignature(sig)
    }

    // This function constructs a canonical byte representation
    // for the MixBatchOutput minus the signature field.
    private fun createCanonicalBytes(batch: MixBatchOutput): ByteArray {
        // Convert header, ciphertextsMatrix, and proofsMatrix to a consistent byte format

        val sb = StringBuilder()

        sb.append(batch.header.toByteArray().contentToString())
        batch.ciphertextsMatrix.forEach { col ->
            col.forEach { c -> sb.append(c.toByteArray().contentToString()) }
        }
        batch.proofsMatrix.forEach { col ->
            col.forEach { p -> sb.append(p.toByteArray().contentToString()) }
        }
        return sb.toString().toByteArray()
    }
}
