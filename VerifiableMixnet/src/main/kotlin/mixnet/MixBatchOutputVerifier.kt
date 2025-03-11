package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Crypto
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoUtils
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey

/**
 * A Verifier for Mixnet proofs.
 *
 * The verifier is make a recursive verification of the MixBatchOutput.
 * For each proof, this verifier recomputes the global challenge by concatenating all commitments,
 * checks that the branch challenges sum to the global challenge,
 * and then verifies each branch using the provided branch challenge.
 */
class MixBatchOutputVerifier(
    private val domainParameters: ECDomainParameters,
    private val publicKey: PublicKey
) {

    /**
     * Verifies the OR-proof for the 2×2 "Switch" scenario.
     *
     * @param orProof The OR-proof to verify.
     */
    fun verifySingleOrProof(
        mix2Proof: Mixing.Mix2Proof,
        // Original ciphertexts (for the inputs)
        a1: GroupElement, a2: GroupElement,
        b1: GroupElement, b2: GroupElement,
        // Final ciphertexts (for the outputs)
        c1: GroupElement, c2: GroupElement,
        d1: GroupElement, d2: GroupElement
    ): Boolean {

        // 1) Deserialize the OR-proof.
        val orProof: ZKPOrProof = deserializeZKP(mix2Proof)

        // 2) Recompute the global challenge by concatenating all commitments.
        val combinedGlobalChallenge = computeGlobalChallengeCombined(orProof)
        orProof.challengeB = combinedGlobalChallenge.subtract(orProof.challengeA).mod(domainParameters.n)

        // 3) Verify each branch using the provided branch challenge.
        // For branch A, assume the pairing: (A → C) and (B → D)
        val okBranchA = verifyAndProofWithProvidedChallenge(
            andProof = orProof.proofA,
            providedChallenge = orProof.challengeA,
            a1, a2, c1, c2,
            b1, b2, d1, d2
        )
        // For branch B, assume the pairing is swapped: (B → C) and (A → D)
        val okBranchB = verifyAndProofWithProvidedChallenge(
            andProof = orProof.proofB,
            providedChallenge = orProof.challengeB,
            b1, b2, c1, c2,
            a1, a2, d1, d2
        )

        val result = okBranchA && okBranchB
        if (!result) {
            println("Verifier: One or both branches do not verify. OR-Proof rejected.")
        } else {
//            println("Verifier: Both branches verify. OR-Proof accepted.")
        }
        return result
    }


    /**
     * Verifies an AND‑proof branch using the provided branch challenge.
     *
     * @param andProof The AND‑proof to verify.
     * @param providedChallenge The branch challenge to use for verification.
     */
    private fun verifyAndProofWithProvidedChallenge(
        andProof: ZKPAndProof,
        providedChallenge: BigInteger,
        // For first sub‑proof:
        a1: GroupElement, a2: GroupElement, c1: GroupElement, c2: GroupElement,
        // For second sub‑proof:
        b1: GroupElement, b2: GroupElement, d1: GroupElement, d2: GroupElement
    ): Boolean {
        val ok1 = verifySingleDLProofProvidedChallenge(
            proof = andProof.proof1,
            a1 = a1, a2 = a2, c1 = c1, c2 = c2,
            providedChallenge = providedChallenge
        )
        val ok2 = verifySingleDLProofProvidedChallenge(
            proof = andProof.proof2,
            a1 = b1, a2 = b2, c1 = d1, c2 = d2,
            providedChallenge = providedChallenge
        )
        return ok1 && ok2
    }

    /**
     * Verifies a single Schnorr sub‑proof using the provided challenge.
     *
     * @param proof The Schnorr proof to verify.
     * @param providedChallenge The challenge to use for verification.
     */
    private fun verifySingleDLProofProvidedChallenge(
        proof: SchnorrProofDL,
        a1: GroupElement, a2: GroupElement,
        c1: GroupElement, c2: GroupElement,
        providedChallenge: BigInteger
    ): Boolean {
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)
        val hPoint  = CryptoUtils.extractECPointFromPublicKey(publicKey)

        // Compute X = c1 - a1 and Y = c2 - a2.
        val XPoint = c1Point.add(a1Point.negate()).normalize()
        val YPoint = c2Point.add(a2Point.negate()).normalize()

        val A_gPoint = CryptoUtils.deserializeGroupElement(proof.A_g, domainParameters)
        val A_hPoint = CryptoUtils.deserializeGroupElement(proof.A_h, domainParameters)

        val lhsG = domainParameters.g.multiply(proof.z).normalize()
        val lhsH = hPoint.multiply(proof.z).normalize()

        val rhsG = A_gPoint.add(XPoint.multiply(providedChallenge)).normalize()
        val rhsH = A_hPoint.add(YPoint.multiply(providedChallenge)).normalize()

        return (lhsG == rhsG) && (lhsH == rhsH)
    }


    /**
     * Recursively verifies the entire MixBatchOutput by processing specified rows and columns.
     *
     * @param mixBatchOutput The MixBatchOutput to verify.
     * @return True if all proofs are valid, False otherwise.
     */
    fun verifyMixBatchOutput(mixBatchOutput: MixBatchOutput): Boolean {
        // Start the recursive verification covering all rows and columns
        return verifyRecursive(
            proofsMatrix = mixBatchOutput.proofsMatrix,
            ciphertextsMatrix = mixBatchOutput.ciphertextsMatrix
        )
    }

    /**
     * Recursive helper function to verify a submatrix of MixBatchOutput.
     *
     * @param proofsMatrix The subset of proofs to verify.
     * @param ciphertextsMatrix The subset of ciphertexts corresponding to the proofs.
     * @return True if all proofs in the specified submatrix are valid, False otherwise.
     */
    private fun verifyRecursive(
        proofsMatrix: List<List<Mixing.Mix2Proof>>,
        ciphertextsMatrix: List<List<Crypto.RerandomizableEncryptedMessage>>
    ): Boolean {
        // Base Case: If there are no columns to process, return true
        if (proofsMatrix.isEmpty() || proofsMatrix[0].isEmpty()) {
            return true
        }

        val numCols = proofsMatrix[0].size

        // Base Case: If only one column remains, process it directly
        if (numCols == 1) {
            return verifySingleColumn(proofsMatrix, ciphertextsMatrix.map { it[0] }, ciphertextsMatrix.map { it[1] }, colIdx = 0)
        }

        // Recursive Case: Process first and last columns
        val firstColIdx = 0
        val lastColIdx = numCols - 1

        // Extract the first and last columns for the current subset of rows
        val firstCol = ciphertextsMatrix.map { it[firstColIdx] }
        var firstColPlus1 = ciphertextsMatrix.map { it[firstColIdx + 1] }
        firstColPlus1 = applyLastColMap(firstColPlus1)

        val numColsCipher = ciphertextsMatrix[0].size
        val lastColIdxCipher = numColsCipher - 1

        val lastCol = ciphertextsMatrix.map { it[lastColIdxCipher] }
        var lastColMinus1 = ciphertextsMatrix.map { it[lastColIdxCipher - 1] }
        lastColMinus1 = applyLastColMap(lastColMinus1)

        if (!verifySingleColumn(proofsMatrix, firstCol, firstColPlus1, firstColIdx)) {
            return false
        }

        if (!verifySingleColumn(proofsMatrix, lastColMinus1, lastCol, lastColIdx)) {
            return false
        }

        // Reconstruct the inner submatrices by excluding the first and last columns
        val innerProofsMatrix = proofsMatrix.map { it.subList(1, it.size - 1) }
        val innerCiphertextsMatrix = ciphertextsMatrix.map { it.subList(1, it.size - 1) }

        // Split the rows into upper and lower subsets
        var midRow = proofsMatrix.size / 2
        val upperProofs = innerProofsMatrix.take(midRow)
        val lowerProofs = innerProofsMatrix.drop(midRow)

        midRow = ciphertextsMatrix.size / 2
        val upperCiphertexts = innerCiphertextsMatrix.take(midRow)
        val lowerCiphertexts = innerCiphertextsMatrix.drop(midRow)

        // Recursive call for the upper subset
        if (!verifyRecursive(upperProofs, upperCiphertexts)) {
            return false
        }

        // Recursive call for the lower subset
        if (!verifyRecursive(lowerProofs, lowerCiphertexts)) {
            return false
        }

        // If all recursive calls pass, return true
        return true
    }

    /**
     * Verifies a single column of proofs.
     *
     * @param proofsMatrix The subset of proofs to verify (single column).
     * @param ciphertextsMatrix The subset of ciphertexts corresponding to the proofs.
     * @return True if all proofs in the column are valid, False otherwise.
     */
    private fun verifySingleColumn(
        proofsMatrix: List<List<Mixing.Mix2Proof>>,
        firstColCipher : List<Crypto.RerandomizableEncryptedMessage>,
        lastColCipher : List<Crypto.RerandomizableEncryptedMessage>,
        colIdx: Int = 0
    ): Boolean {

        for (rowIdx in proofsMatrix.indices) {
            val proof = proofsMatrix[rowIdx][colIdx]

            // Extract corresponding ciphertexts
            val aCiphertext = CryptoUtils.unwrapCiphertext(firstColCipher[rowIdx * 2])
            val bCiphertext = CryptoUtils.unwrapCiphertext(firstColCipher[rowIdx * 2 + 1])
            val cCiphertext = CryptoUtils.unwrapCiphertext(lastColCipher[rowIdx * 2])
            val dCiphertext = CryptoUtils.unwrapCiphertext(lastColCipher[rowIdx * 2 + 1])

            // Verify the proof
            if (!verifySingleOrProof(
                    proof,
                    aCiphertext.c1, aCiphertext.c2,
                    bCiphertext.c1, bCiphertext.c2,
                    cCiphertext.c1, cCiphertext.c2,
                    dCiphertext.c1, dCiphertext.c2
                )
            ) {
                println("Proof verification failed for row $rowIdx, for column $colIdx.")
                return false
            }
        }

        return true
    }


    /*
        * Helper functions for recursive verification
     */

    /**
     * Maps the last column's result to finalize the permutation.
     */
    private fun applyLastColMap(votes:
                                List<Crypto. RerandomizableEncryptedMessage>):
            List<Crypto. RerandomizableEncryptedMessage> {
        // Reverse of applyFirstColMap
        val size = votes.size
        val half = size / 2
        val result = MutableList(size) { votes[it] }

        for (i in 0 until half) {
            result[2 * i] = votes[i]
            result[2 * i + 1] = votes[i + half]
        }
        return result.toList()
    }

    /**
     * Computes the global challenge exactly as the prover does by concatenating the serialized commitments
     * from both AND-proof branches.
     *
     * @param orProof The OR-proof containing the AND-proofs to combine.
     */
    private fun computeGlobalChallengeCombined(orProof: ZKPOrProof): BigInteger {
        val baos = ByteArrayOutputStream()
        fun putAndProof(andProof: ZKPAndProof) {
            baos.write(andProof.proof1.A_g.data.toByteArray())
            baos.write(andProof.proof1.A_h.data.toByteArray())
            baos.write(andProof.proof2.A_g.data.toByteArray())
            baos.write(andProof.proof2.A_h.data.toByteArray())
        }
        putAndProof(orProof.proofA)
        putAndProof(orProof.proofB)
        val eBytes = baos.toByteArray()
        val e = CryptoUtils.hashToBigInteger(eBytes).mod(domainParameters.n)
        return e
    }

    private fun deserializeZKP(mix2Proof: Mixing.Mix2Proof): ZKPOrProof {
        val proofA = ZKPAndProof(
            proof1 = SchnorrProofDL(
                A_g = mix2Proof.firstMessage.clause0.clause0.gr,
                A_h = mix2Proof.firstMessage.clause0.clause0.hr,
                z = mix2Proof.finalMessage.clause0.clause0.xcr.toBigInteger()
            ),
            proof2 = SchnorrProofDL(
                A_g = mix2Proof.firstMessage.clause0.clause1.gr,
                A_h = mix2Proof.firstMessage.clause0.clause1.hr,
                z = mix2Proof.finalMessage.clause0.clause1.xcr.toBigInteger()
            )
        )

        val proofB = ZKPAndProof(
            proof1 = SchnorrProofDL(
                A_g = mix2Proof.firstMessage.clause1.clause0.gr,
                A_h = mix2Proof.firstMessage.clause1.clause0.hr,
                z = mix2Proof.finalMessage.clause1.clause0.xcr.toBigInteger()
            ),
            proof2 = SchnorrProofDL(
                A_g = mix2Proof.firstMessage.clause1.clause1.gr,
                A_h = mix2Proof.firstMessage.clause1.clause1.hr,
                z = mix2Proof.finalMessage.clause1.clause1.xcr.toBigInteger()
            )
        )

        return ZKPOrProof(
            proofA = proofA,
            proofB = proofB,
            challengeA = mix2Proof.finalMessage.c0.toBigInteger(),
            challengeB = BigInteger.ZERO, // The protobuf message does not contain challengeB
            fullChallenge = BigInteger.ZERO // The protobuf message does not contain fullChallenge
        )
    }

    private fun meerkat.protobuf.Crypto.BigInteger.toBigInteger(): BigInteger {
        return BigInteger(this.data.toByteArray())
    }

    /**
     * Verifies a decryption proof.
     *
     * For a given decryption share, the server’s proof (of type SchnorrProofDL) shows that
     * the same secret s was used to compute both its public share (h = g^s) and its decryption share (d = c1^s).
     *
     * The function performs the following steps:
     * 1. Concatenates the byte arrays of the commitments A_g and A_h from the proof,
     *    and the serialized forms of h_i and d_i.
     * 2. Computes the challenge as e = hash(concatenatedBytes) mod n.
     * 3. Checks that:
     *       g^z = A_g + h_i * e
     *       c1^z = A_h + d_i * e
     *
     * @param proof The SchnorrProofDL containing A_g, A_h and response z.
     * @param h_iSerialized The serialized form of the server’s public share (GroupElement).
     * @param d_iSerialized The serialized form of the server’s decryption share (GroupElement).
     * @param c1Serialized  The serialized form of c1 (used as the second base).
     * @return true if the proof verifies, false otherwise.
     */
    fun verifyDecryptionProof(
        proof: SchnorrProofDL,
        h_iSerialized: GroupElement,
        d_iSerialized: GroupElement,
        c1Serialized: GroupElement
    ): Boolean {
        // Concatenate the commitments and the serialized public and decryption shares.
        val baos = ByteArrayOutputStream()
        fun putCommit(A_g: GroupElement, A_h: GroupElement) {
            baos.write(A_g.data.toByteArray())
            baos.write(A_h.data.toByteArray())
        }
        putCommit(proof.A_g, proof.A_h)
        baos.write(h_iSerialized.data.toByteArray())
        baos.write(d_iSerialized.data.toByteArray())

        // Compute the challenge e.
        val challenge = CryptoUtils.hashToBigInteger(baos.toByteArray()).mod(domainParameters.n)

        // Compute the left-hand side for the first equation: g^z.
        val lhs1 = domainParameters.g.multiply(proof.z).normalize()
        // Compute the right-hand side: A_g + h_i * e.
        val rhs1 = CryptoUtils.deserializeGroupElement(proof.A_g, domainParameters)
            .add(CryptoUtils.deserializeGroupElement(h_iSerialized, domainParameters).multiply(challenge))
            .normalize()

        // Compute the left-hand side for the second equation: c1^z.
        val lhs2 = CryptoUtils.deserializeGroupElement(c1Serialized, domainParameters)
            .multiply(proof.z).normalize()
        // Compute the right-hand side: A_h + d_i * e.
        val rhs2 = CryptoUtils.deserializeGroupElement(proof.A_h, domainParameters)
            .add(CryptoUtils.deserializeGroupElement(d_iSerialized, domainParameters).multiply(challenge))
            .normalize()

        return lhs1 == rhs1 && lhs2 == rhs2
    }

}
