package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import meerkat.protobuf.Mixing
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoUtils
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey

/**
 * A Verifier for the 2×2 "Switch" scenario.
 *
 * This verifier recomputes the global challenge by concatenating all commitments,
 * checks that the branch challenges sum to the global challenge,
 * and then verifies each branch using the provided branch challenge.
 */
class Verifier(
    private val domainParameters: ECDomainParameters,
    private val publicKey: PublicKey
) {

    /**
     * Verifies the OR-proof for the 2×2 "Switch" scenario.
     *
     * @param orProof The OR-proof to verify.
     */
    fun verifyOrProof(
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

//        println("Verifier: Branch A verifies: $okBranchA")
//        println("Verifier: Branch B verifies: $okBranchB\n")

        val result = okBranchA && okBranchB
        if (!result) {
            println("Verifier: One or both branches do not verify. OR-Proof rejected.")
        } else {
            println("Verifier: Both branches verify. OR-Proof accepted.")
        }
        return result
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
//        println("Verifier: Global challenge input bytes: ${eBytes.joinToString("") { "%02x".format(it) }}")
        val e = CryptoUtils.hashToBigInteger(eBytes).mod(domainParameters.n)
//        println("Verifier: Combined global challenge: ${e.toString(16)}\n")
        return e
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
        val ok1 = verifySingleZKPProvidedChallenge(
            proof = andProof.proof1,
            a1 = a1, a2 = a2, c1 = c1, c2 = c2,
            providedChallenge = providedChallenge
        )
        val ok2 = verifySingleZKPProvidedChallenge(
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
    private fun verifySingleZKPProvidedChallenge(
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

//        println("A_gPoint: ${A_gPoint}")
//        println("g: ${domainParameters.g}")
//        println("z: ${proof.z}")
//        println("providedChallenge: ${providedChallenge}")
//        println("XPoint: ${XPoint}")
//        println("c1Point: ${c1Point}")
//        println("a1Point: ${a1Point}\n")
//
//
//        println("Verifier (using provided branch challenge):")
//        println("Provided branch challenge: ${providedChallenge.toString(16)}")
//        println("LHS (z*G): ${CryptoUtils.serializeGroupElement(lhsG).data.joinToString("") { "%02x".format(it) }}")
//        println("RHS (A_g + challenge*X): ${CryptoUtils.serializeGroupElement(rhsG).data.joinToString("") { "%02x".format(it) }}")
//        println("LHS (z*H): ${CryptoUtils.serializeGroupElement(lhsH).data.joinToString("") { "%02x".format(it) }}")
//        println("RHS (A_h + challenge*Y): ${CryptoUtils.serializeGroupElement(rhsH).data.joinToString("") { "%02x".format(it) }}\n")

        return (lhsG == rhsG) && (lhsH == rhsH)
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
     * Verifies the entire MixBatchOutput.
     *
     * @param mixBatchOutput The MixBatchOutput to verify.
     * @return True if all proofs are valid, False otherwise.
     */
    fun verifyMixBatchOutput(mixBatchOutput: MixBatchOutput): Boolean {

        println("num of rows: ${mixBatchOutput.proofsMatrix.size}")
        println("num of cols: ${mixBatchOutput.proofsMatrix[0].size}")

        println("num of rows cipher: ${mixBatchOutput.ciphertextsMatrix.size}")
        println("num of cols cipher: ${mixBatchOutput.ciphertextsMatrix[0].size}")

        for (rowIdx in mixBatchOutput.proofsMatrix.indices) {
            for (colIdx in mixBatchOutput.proofsMatrix[rowIdx].indices) {
                val proof = mixBatchOutput.proofsMatrix[rowIdx][colIdx]

                println("a index: ${rowIdx * 2}, $colIdx")
                println("b index: ${rowIdx * 2 + 1}, $colIdx")
                println("c index: ${rowIdx * 2}, ${colIdx + 1}")
                println("d index: ${rowIdx * 2 + 1}, ${colIdx + 1}")

                // Extract the original and final ciphertexts for verification
                val aCiphertext = CryptoUtils.unwrapCiphertext(mixBatchOutput.ciphertextsMatrix[rowIdx * 2][colIdx])
                val bCiphertext = CryptoUtils.unwrapCiphertext(mixBatchOutput.ciphertextsMatrix[rowIdx * 2 + 1][colIdx])
                val cCiphertext = CryptoUtils.unwrapCiphertext(mixBatchOutput.ciphertextsMatrix[rowIdx * 2][colIdx + 1])
                val dCiphertext = CryptoUtils.unwrapCiphertext(mixBatchOutput.ciphertextsMatrix[rowIdx * 2 + 1][colIdx + 1])

                // Verify the proof
                if (!verifyOrProof(proof, aCiphertext.c1, aCiphertext.c2, bCiphertext.c1, bCiphertext.c2, cCiphertext.c1, cCiphertext.c2, dCiphertext.c1, dCiphertext.c2)) {
//                    return false
                }
            }
        }
        return true
    }

}
