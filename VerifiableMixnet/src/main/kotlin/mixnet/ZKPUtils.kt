package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import org.bouncycastle.asn1.x509.ObjectDigestInfo.publicKey
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.BigIntegerUtils
import org.example.crypto.CryptoUtils
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.SecureRandom

object ZKPUtils {

//    /**
//     * Generates a real Schnorr Discrete-Log-Equality Proof.
//     * (Unchanged from before.)
//     */
//    fun generateSingleZKP(
//        a1: GroupElement,
//        a2: GroupElement,
//        c1: GroupElement,
//        c2: GroupElement,
//        r: BigInteger,
//        publicKey: PublicKey,
//        domainParameters: ECDomainParameters
//    ): SchnorrProofDL {
//        // Deserialize inputs.
//        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
//        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
//        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
//        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)
//        val hPoint  = CryptoUtils.extractECPointFromPublicKey(publicKey)
//
//        // Compute X = c1 – a1 and Y = c2 – a2.
//        val XPoint = c1Point.add(a1Point.negate()).normalize()
//        val YPoint = c2Point.add(a2Point.negate()).normalize()
//
//        // Choose ephemeral t and compute commitments.
//        val t = BigIntegerUtils.randomBigInteger(domainParameters.n, SecureRandom.getInstanceStrong())
//        val A_gPoint = domainParameters.g.multiply(t).normalize()
//        val A_hPoint = hPoint.multiply(t).normalize()
//
//        // Serialize the group elements.
//        val A_gSer = CryptoUtils.serializeGroupElement(A_gPoint)
//        val A_hSer = CryptoUtils.serializeGroupElement(A_hPoint)
//        val XSer   = CryptoUtils.serializeGroupElement(XPoint)
//        val YSer   = CryptoUtils.serializeGroupElement(YPoint)
//
//        // Compute challenge using Fiat–Shamir.
//        val c = hashChallenge(A_gSer, A_hSer, XSer, YSer, publicKey, domainParameters)
//
//        // Response: z = t + c*r mod n.
//        val z = t.add(c.multiply(r)).mod(domainParameters.n)
//        return SchnorrProofDL(A_gSer, A_hSer, z)
//    }

    /**
     * (One-shot fake simulation)
     *
     * Simulates a Schnorr proof “in one shot” without rewinding. In a sigma‑protocol OR‑proof,
     * it is acceptable to choose a fake challenge and response arbitrarily then compute the fake
     * commitment as:
     *
     *    A_g = zFake*G – cFake*X
     *    A_h = zFake*H – cFake*Y
     *
     * Later, when the global challenge is computed, the fake branch’s challenge is simply used as-is.
     */
    private fun simulateFakeSubProof(
        a1: GroupElement,
        a2: GroupElement,
        c1: GroupElement,
        c2: GroupElement,
        publicKey: PublicKey,
        domainParameters: ECDomainParameters
    ): SchnorrCommitFake {
        val n = domainParameters.n
        val rnd = SecureRandom.getInstanceStrong()

        // Deserialize to compute X and Y.
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)
        val hPoint  = CryptoUtils.extractECPointFromPublicKey(publicKey)
        val XPoint = c1Point.add(a1Point.negate()).normalize()
        val YPoint = c2Point.add(a2Point.negate()).normalize()

        // One-shot: pick random fake challenge and response.
        val cFake = BigIntegerUtils.randomBigInteger(n, rnd)
        val zFake = BigIntegerUtils.randomBigInteger(n, rnd)

        // Compute the fake commitments.
        val A_gPoint = domainParameters.g.multiply(zFake)
            .subtract(XPoint.multiply(cFake)).normalize()
        val A_hPoint = hPoint.multiply(zFake)
            .subtract(YPoint.multiply(cFake)).normalize()

        return SchnorrCommitFake(
            A_g = CryptoUtils.serializeGroupElement(A_gPoint),
            A_h = CryptoUtils.serializeGroupElement(A_hPoint),
            cFake = cFake,
            zFake = zFake
        )
    }

    /**
     * Generates an OR‑proof that shows that EITHER
     *   (A→C and B→D are a re‑encryption) is the real branch
     * OR
     *   (B→C and A→D) is the real branch.
     *
     * The simulation for the fake branch uses the one-shot fake simulation (above).
     * (The ordering of parameters is made explicit.)
     */
    fun generateOrProof(
        a1: GroupElement, a2: GroupElement,
        b1: GroupElement, b2: GroupElement,
        c1: GroupElement, c2: GroupElement,
        d1: GroupElement, d2: GroupElement,
        rC: BigInteger,
        rD: BigInteger,
        switchFlag: Int,
        publicKey: PublicKey,
        domainParameters: ECDomainParameters
    ): ZKPOrProof {
        require(switchFlag == 0 || switchFlag == 1)

        // Determine which branch is real and which is fake.
        val real1_a1: FiveTuple
        val real2_a1: FiveTuple
        val fake1_a1: FourTuple
        val fake2_a1: FourTuple

        if (switchFlag == 0) {
            // Real branch: (A→C, B→D)
            real1_a1 = FiveTuple(a1, a2, c1, c2, rC)
            real2_a1 = FiveTuple(b1, b2, d1, d2, rD)
            // Fake branch: (B→C, A→D)
            fake1_a1 = FourTuple(b1, b2, c1, c2)
            fake2_a1 = FourTuple(a1, a2, d1, d2)
        } else {
            // Real branch: (B→C, A→D)
            real1_a1 = FiveTuple(b1, b2, c1, c2, rC)
            real2_a1 = FiveTuple(a1, a2, d1, d2, rD)
            // Fake branch: (A→C, B→D)
            fake1_a1 = FourTuple(a1, a2, c1, c2)
            fake2_a1 = FourTuple(b1, b2, d1, d2)
        }

        // 1) Compute commitments for the real branch.
        val realCommit1 = commitRealSubProof(
            real1_a1.a1, real1_a1.a2, real1_a1.c1, real1_a1.c2, real1_a1.r,
            publicKey, domainParameters
        )
        val realCommit2 = commitRealSubProof(
            real2_a1.a1, real2_a1.a2, real2_a1.c1, real2_a1.c2, real2_a1.r,
            publicKey, domainParameters
        )

        // 2) Simulate commitments for the fake branch (one-shot).
        val fakeCommit1 = simulateFakeSubProof(
            fake1_a1.a1, fake1_a1.a2, fake1_a1.c1, fake1_a1.c2,
            publicKey, domainParameters
        )
        val fakeCommit2 = simulateFakeSubProof(
            fake2_a1.a1, fake2_a1.a2, fake2_a1.c1, fake2_a1.c2,
            publicKey, domainParameters
        )

        // 3) Compute the global challenge. Here we use a dynamically built byte array
        //    so that only the exact commitment bytes are hashed (avoiding extra padding).
        val baos = ByteArrayOutputStream()
        fun putCommit(A_g: GroupElement, A_h: GroupElement) {
            baos.write(A_g.data.toByteArray())
            baos.write(A_h.data.toByteArray())
        }
        putCommit(realCommit1.A_g, realCommit1.A_h)
        putCommit(realCommit2.A_g, realCommit2.A_h)
        putCommit(fakeCommit1.A_g, fakeCommit1.A_h)
        putCommit(fakeCommit2.A_g, fakeCommit2.A_h)
        val eBytes = baos.toByteArray()
        val e = CryptoUtils.hashToBigInteger(eBytes).mod(domainParameters.n)
        println("Prover: Global challenge input bytes: ${eBytes.joinToString("") { "%02x".format(it) }}")
        println("Prover: Computed global challenge: ${e.toString(16)}")

        // 4) Set the real branch’s challenge to be:
        //    cReal = e – (cFake1 + cFake2) mod n.
        val cFakeTotal = fakeCommit1.cFake.add(fakeCommit2.cFake).mod(domainParameters.n)
        val cReal = e.subtract(cFakeTotal).mod(domainParameters.n)

        // 5) Finalize the real branch by computing responses with the challenge cReal.
        val proofReal1 = finalizeRealSubProof(realCommit1, cReal, real1_a1.r, domainParameters)
        val proofReal2 = finalizeRealSubProof(realCommit2, cReal, real2_a1.r, domainParameters)

        // 6) The fake branch proofs are taken directly from the simulation.
        val proofFake1 = SchnorrProofDL(fakeCommit1.A_g, fakeCommit1.A_h, fakeCommit1.zFake)
        val proofFake2 = SchnorrProofDL(fakeCommit2.A_g, fakeCommit2.A_h, fakeCommit2.zFake)

        val realAnd = ZKPAndProof(proofReal1, proofReal2)
        val fakeAnd = ZKPAndProof(proofFake1, proofFake2)

        val (challengeA, challengeB, proofA, proofB) =
            if (switchFlag == 0)
                Quadruple(cReal, cFakeTotal, realAnd, fakeAnd)
            else
                Quadruple(cReal, cFakeTotal, realAnd, fakeAnd)

        return ZKPOrProof(
            proofA = proofA,
            proofB = proofB,
            challengeA = challengeA,
            challengeB = challengeB,
            fullChallenge = e
        )
    }

//    /**
//     * Helper: Computes a Fiat–Shamir challenge from the given commitments.
//     * We build a dynamic byte array (via ByteArrayOutputStream) to avoid unused padding.
//     */
//    private fun hashChallenge(
//        A_gSer: GroupElement,
//        A_hSer: GroupElement,
//        XSer: GroupElement,
//        YSer: GroupElement,
//        publicKey: PublicKey,
//        domainParameters: ECDomainParameters
//    ): BigInteger {
//        val baos = ByteArrayOutputStream()
//        baos.write(A_gSer.data.toByteArray())
//        baos.write(A_hSer.data.toByteArray())
//        baos.write(XSer.data.toByteArray())
//        baos.write(YSer.data.toByteArray())
//        val combined = baos.toByteArray()
//        val cRaw = CryptoUtils.hashToBigInteger(combined)
//        return cRaw.mod(domainParameters.n)
//    }

    /**
     * Commits a real sub-proof by choosing a random ephemeral exponent t,
     * and computing A_g = G^t and A_h = H^t.
     */
    private fun commitRealSubProof(
        a1: GroupElement,
        a2: GroupElement,
        c1: GroupElement,
        c2: GroupElement,
        r: BigInteger,
        publicKey: PublicKey,
        domainParameters: ECDomainParameters
    ): SchnorrCommitReal {
        val t = BigIntegerUtils.randomBigInteger(domainParameters.n, SecureRandom.getInstanceStrong())
        val A_gPoint = domainParameters.g.multiply(t).normalize()
        val hPoint = CryptoUtils.extractECPointFromPublicKey(publicKey)
        val A_hPoint = hPoint.multiply(t).normalize()
        return SchnorrCommitReal(
            A_g = CryptoUtils.serializeGroupElement(A_gPoint),
            A_h = CryptoUtils.serializeGroupElement(A_hPoint),
            t   = t
        )
    }

    /**
     * Finalizes a real sub-proof by computing z = t + (challengeReal * r) mod n.
     */
    private fun finalizeRealSubProof(
        commit: SchnorrCommitReal,
        challengeReal: BigInteger,
        r: BigInteger,
        domainParameters: ECDomainParameters
    ): SchnorrProofDL {
        val z = commit.t.add(challengeReal.multiply(r)).mod(domainParameters.n)
        return SchnorrProofDL(
            A_g = commit.A_g,
            A_h = commit.A_h,
            z   = z
        )
    }
}

/**
 * A helper data class (and alias) to hold four values.
 */
private data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

/**
 * Tuple classes for organizing parameters.
 */
private data class FiveTuple(
    val a1: GroupElement,
    val a2: GroupElement,
    val c1: GroupElement,
    val c2: GroupElement,
    val r:  BigInteger
)
private data class FourTuple(
    val a1: GroupElement,
    val a2: GroupElement,
    val c1: GroupElement,
    val c2: GroupElement
)