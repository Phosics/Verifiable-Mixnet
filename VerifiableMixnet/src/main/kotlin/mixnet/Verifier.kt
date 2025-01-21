package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoUtils
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey

/**
 * A Verifier for the 2×2 "Switch" scenario.
 *
 * This modified version computes the global challenge exactly as the prover does:
 * it concatenates all commitments (two per AND‑proof, i.e. for both branches) via
 * a ByteArrayOutputStream, hashes the result to get e, and then uses the partition
 * of e (into challengeA and challengeB) for verifying each branch.
 *
 * In the final verification, each AND‑proof is checked using the provided branch challenge.
 */
class Verifier(
    private val domainParameters: ECDomainParameters,
    private val publicKey: PublicKey
) {

    /**
     * Verifies the OR‑proof by checking:
     *  1. The sum of the branch challenges equals the combined global challenge e.
     *  2. The global challenge computed from all commitments matches.
     *  3. Each branch’s AND‑proof verifies when using its supplied challenge.
     * At least one branch must verify.
     */
    fun verifyOrProof(
        orProof: ZKPOrProof,
        // Original ciphertexts (a, b)
        a1: GroupElement, a2: GroupElement,
        b1: GroupElement, b2: GroupElement,
        // Final ciphertexts (c, d)
        c1: GroupElement, c2: GroupElement,
        d1: GroupElement, d2: GroupElement
    ): Boolean {
        // 1) Check that the sum of branch challenges equals the global challenge.
        val sumChallenges = orProof.challengeA.add(orProof.challengeB).mod(domainParameters.n)
        if (sumChallenges != orProof.fullChallenge) {
            println("Global challenge mismatch: challengeA + challengeB != fullChallenge.")
            return false
        }

        // 2) Recompute the global challenge from all 4 commitments, exactly as the prover does.
        val combinedGlobalChallenge = computeGlobalChallengeCombined(orProof)
        if (combinedGlobalChallenge != orProof.fullChallenge) {
            println("Combined global challenge does not match fullChallenge.")
            return false
        }

        // 3) Verify each branch using its supplied challenge.
        // Here we assume that for each branch, the prover used the same challenge for both sub‑proofs.
        val okBranchA = verifyAndProofWithChallenge(
            andProof = orProof.proofA,
            branchChallenge = orProof.challengeA,
            // For branch A, assume the corresponding statement is:
            //   first sub-proof: (A → C)  (i.e. a1, a2, c1, c2)
            //   second sub-proof: (B → D) (i.e. b1, b2, d1, d2)
            a1, a2, c1, c2,
            b1, b2, d1, d2
        )

        val okBranchB = verifyAndProofWithChallenge(
            andProof = orProof.proofB,
            branchChallenge = orProof.challengeB,
            // For branch B, the ciphertext pairing is swapped:
            //   first sub-proof: (B → C)  (i.e. b1, b2, c1, c2)
            //   second sub-proof: (A → D) (i.e. a1, a2, d1, d2)
            b1, b2, c1, c2,
            a1, a2, d1, d2
        )

        if(okBranchA) println("Branch A verifies.")
        if(okBranchB) println("Branch B verifies.")

        val result = okBranchA || okBranchB
        if (!result) {
            println("Neither branch verifies under the standard equations.")
        }
        return result
    }

    /**
     * Computes the global challenge exactly like the prover does,
     * by concatenating the serialized commitments from both AND-proof branches.
     */
    private fun computeGlobalChallengeCombined(orProof: ZKPOrProof): BigInteger {
        val baos = ByteArrayOutputStream()
        fun putAndProof(andProof: ZKPAndProof) {
            // Each AND-proof consists of two Schnorr sub-proofs.
            baos.write(andProof.proof1.A_g.data.toByteArray())
            baos.write(andProof.proof1.A_h.data.toByteArray())
            baos.write(andProof.proof2.A_g.data.toByteArray())
            baos.write(andProof.proof2.A_h.data.toByteArray())
        }
        putAndProof(orProof.proofA)
        putAndProof(orProof.proofB)
        val eBytes = baos.toByteArray()
        println("Verifier: Global challenge input bytes: ${eBytes.joinToString("") { "%02x".format(it) }}")
        val e = CryptoUtils.hashToBigInteger(eBytes).mod(domainParameters.n)
        println("Verifier: Combined global challenge: ${e.toString(16)}\n")
        return e
    }

    /**
     * Verifies an AND-proof branch using the given branch challenge.
     * For each sub-proof in the branch, it checks the standard Schnorr equations using that challenge.
     */
    private fun verifyAndProofWithChallenge(
        andProof: ZKPAndProof,
        branchChallenge: BigInteger,
        // For first sub-proof:
        a1: GroupElement, a2: GroupElement, c1: GroupElement, c2: GroupElement,
        // For second sub-proof:
        b1: GroupElement, b2: GroupElement, d1: GroupElement, d2: GroupElement
    ): Boolean {
        val ok1 = verifySingleZKPWithChallenge(
            proof = andProof.proof1,
            a1 = a1, a2 = a2, c1 = c1, c2 = c2,
            challenge = branchChallenge
        )
        val ok2 = verifySingleZKPWithChallenge(
            proof = andProof.proof2,
            a1 = b1, a2 = b2, c1 = d1, c2 = d2,
            challenge = branchChallenge
        )
        return ok1 && ok2
    }

    /**
     * Verifies a single Schnorr DLEQ sub-proof using a given challenge.
     * Here, we use the provided challenge (which should be the same for both sub-proofs
     * in the real branch) instead of recomputing it via the statement parameters.
     */
    private fun verifySingleZKPWithChallenge(
        proof: SchnorrProofDL,
        a1: GroupElement, a2: GroupElement, // Original ciphertext components
        c1: GroupElement, c2: GroupElement, // Final ciphertext components
        challenge: BigInteger
    ): Boolean {
        // Deserialize input points.
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)
        val hPoint  = CryptoUtils.extractECPointFromPublicKey(publicKey)

        // Compute differences X = c1 – a1 and Y = c2 – a2.
        val XPoint = c1Point.add(a1Point.negate()).normalize()
        val YPoint = c2Point.add(a2Point.negate()).normalize()

        // Deserialize commitments from proof.
        val A_gPoint = CryptoUtils.deserializeGroupElement(proof.A_g, domainParameters)
        val A_hPoint = CryptoUtils.deserializeGroupElement(proof.A_h, domainParameters)

        // Compute the left-hand sides (LHS).
        val lhsG = domainParameters.g.multiply(proof.z).normalize()
        val lhsH = hPoint.multiply(proof.z).normalize()

        // Compute the right-hand sides (RHS) using the provided branch challenge.
        val rhsG = A_gPoint.add(XPoint.multiply(challenge)).normalize()
        val rhsH = A_hPoint.add(YPoint.multiply(challenge)).normalize()

        println("Verifier (with given challenge):")
        println("Provided challenge: ${challenge.toString(16)}")
        println("LHS (z*G): ${CryptoUtils.serializeGroupElement(lhsG).data.joinToString("") { "%02x".format(it) }}")
        println("RHS (A_g + challenge*X): ${CryptoUtils.serializeGroupElement(rhsG).data.joinToString("") { "%02x".format(it) }}")
        println("LHS (z*H): ${CryptoUtils.serializeGroupElement(lhsH).data.joinToString("") { "%02x".format(it) }}")
        println("RHS (A_h + challenge*Y): ${CryptoUtils.serializeGroupElement(rhsH).data.joinToString("") { "%02x".format(it) }}")

        return (lhsG == rhsG) && (lhsH == rhsH)
    }

    // The original hashChallenge function remains available if needed.
    private fun hashChallenge(
        A_gSer: GroupElement,
        A_hSer: GroupElement,
        XSer: GroupElement,
        YSer: GroupElement,
        publicKey: PublicKey,
        domainParameters: ECDomainParameters
    ): BigInteger {
        val baos = ByteArrayOutputStream()
        baos.write(A_gSer.data.toByteArray())
        baos.write(A_hSer.data.toByteArray())
        baos.write(XSer.data.toByteArray())
        baos.write(YSer.data.toByteArray())
        val combined = baos.toByteArray()
        val cRaw = CryptoUtils.hashToBigInteger(combined)
        return cRaw.mod(domainParameters.n)
    }
}
