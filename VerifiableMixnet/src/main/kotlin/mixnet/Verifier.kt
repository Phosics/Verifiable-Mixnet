package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoUtils
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.PublicKey

/**
 * A Verifier for the 2x2 "Switch" scenario.
 * Contains methods to verify:
 *   - Single Schnorr DLEQ (verifySingleZKP)
 *   - AND of 2 DLEQs (verifyAndProof)
 *   - OR of 2 AND statements (verifyOrProof)
 */
class Verifier(
    private val domainParameters: ECDomainParameters,
    private val publicKey: PublicKey
) {

    /**
     * Verifies a single Schnorr DLEQ proof:
     *   X = c1 - a1, Y = c2 - a2
     *   The proof is valid iff
     *   z*G == A_g + c*X  AND  z*H == A_h + c*Y
     *   where c = H(A_g, A_h, X, Y) mod n.
     */
    fun verifySingleZKP(
        proof: SchnorrProofDL,
        a1: GroupElement,
        a2: GroupElement,
        c1: GroupElement,
        c2: GroupElement
    ): Boolean {
        // 1) Deserialize
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)
        val hPoint  = CryptoUtils.extractECPointFromPublicKey(publicKey)

        // 2) X = c1 - a1, Y = c2 - a2
        val XPoint = c1Point.add(a1Point.negate()).normalize()
        val YPoint = c2Point.add(a2Point.negate()).normalize()

        // 3) Recompute challenge from commitments and X,Y
        val A_gPoint = CryptoUtils.deserializeGroupElement(proof.A_g, domainParameters)
        val A_hPoint = CryptoUtils.deserializeGroupElement(proof.A_h, domainParameters)

        val cComputed = hashChallenge(
            proof.A_g,   // A_g as GroupElement
            proof.A_h,   // A_h
            CryptoUtils.serializeGroupElement(XPoint),
            CryptoUtils.serializeGroupElement(YPoint)
        )

        // 4) Check the equations in additive notation:
        //    z*G == A_g + cComputed*X
        //    z*H == A_h + cComputed*Y
        val z = proof.z

        // Left side
        val lhsG = domainParameters.g.multiply(z).normalize()
        val lhsH = hPoint.multiply(z).normalize()

        // Right side
        val rhsG = A_gPoint.add(XPoint.multiply(cComputed)).normalize()
        val rhsH = A_hPoint.add(YPoint.multiply(cComputed)).normalize()

        return (lhsG == rhsG) && (lhsH == rhsH)
    }

    /**
     * Verifies an AND proof:
     *   - first sub-proof => (c reencrypts a)
     *   - second sub-proof => (d reencrypts b)
     * or any pair you specify by passing the ciphertext pairs.
     */
    fun verifyAndProof(
        andProof: ZKPAndProof,
        a1: GroupElement, a2: GroupElement,
        c1: GroupElement, c2: GroupElement,
        b1: GroupElement, b2: GroupElement,
        d1: GroupElement, d2: GroupElement
    ): Boolean {
        // first sub-proof => "c is reencrypt of a"
        val ok1 = verifySingleZKP(andProof.proof1, a1, a2, c1, c2)
        // second sub-proof => "d is reencrypt of b"
        val ok2 = verifySingleZKP(andProof.proof2, b1, b2, d1, d2)
        return ok1 && ok2
    }

    /**
     * Verifies the OR-proof that covers:
     *   (A side) [c reencrypt a, d reencrypt b]
     *    OR
     *   (B side) [c reencrypt b, d reencrypt a].
     */
    fun verifyOrProof(
        orProof: ZKPOrProof,
        // original ciphertexts (a, b)
        a1: GroupElement, a2: GroupElement,
        b1: GroupElement, b2: GroupElement,
        // final ciphertexts (c, d)
        c1: GroupElement, c2: GroupElement,
        d1: GroupElement, d2: GroupElement
    ): Boolean {
        // 1) Check that challengeA + challengeB == fullChallenge (mod n)
        val sum = orProof.challengeA.add(orProof.challengeB).mod(domainParameters.n)
        if (sum != orProof.fullChallenge) {
            return false
        }

        // 2) Recompute global challenge e' from the commitments
        val ePrime = computeGlobalChallenge(orProof.proofA, orProof.proofB)
        if (ePrime != orProof.fullChallenge) {
            return false
        }

        // 3) Check the "A" side => (c reencrypt a) AND (d reencrypt b)
        val okA = verifyAndProof(
            orProof.proofA,
            a1, a2, c1, c2,
            b1, b2, d1, d2
        )

        // 4) Check the "B" side => (c reencrypt b) AND (d reencrypt a)
        val okB = verifyAndProof(
            orProof.proofB,
            b1, b2, c1, c2,
            a1, a2, d1, d2
        )

        // 5) Accept if either side is valid
        return okA || okB
    }

    /**
     * Re-computes a "global" challenge from the commitments of two AND-proofs
     * (4 single sub-proofs). Typically, we gather (A_g, A_h) from each sub-proof.
     */
    private fun computeGlobalChallenge(
        proofA: ZKPAndProof,
        proofB: ZKPAndProof
    ): BigInteger {
        val buf = ByteBuffer.allocate(4096)
        fun putProofDL(p: SchnorrProofDL) {
            buf.put(p.A_g.data.toByteArray())
            buf.put(p.A_h.data.toByteArray())
        }
        putProofDL(proofA.proof1)
        putProofDL(proofA.proof2)
        putProofDL(proofB.proof1)
        putProofDL(proofB.proof2)

        val cRaw = CryptoUtils.hashToBigInteger(buf.array())
        return cRaw.mod(domainParameters.n)
    }

    /**
     * Same "hashChallenge" technique used in generateSingleZKP.
     */
    private fun hashChallenge(
        A_gSer: GroupElement,
        A_hSer: GroupElement,
        XSer: GroupElement,
        YSer: GroupElement
    ): BigInteger {
        val A_gBytes = A_gSer.data.toByteArray()
        val A_hBytes = A_hSer.data.toByteArray()
        val XBytes   = XSer.data.toByteArray()
        val YBytes   = YSer.data.toByteArray()

        val buf = ByteBuffer.allocate(
            A_gBytes.size + A_hBytes.size + XBytes.size + YBytes.size
        )
        buf.put(A_gBytes)
        buf.put(A_hBytes)
        buf.put(XBytes)
        buf.put(YBytes)

        val cRaw = CryptoUtils.hashToBigInteger(buf.array())
        return cRaw.mod(domainParameters.n)
    }
}