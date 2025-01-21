package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.BigIntegerUtils
import org.example.crypto.CryptoUtils
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.SecureRandom

object ZKPUtils {

    /**
     * Generates an OR‑proof for the 2×2 "Switch" scenario.
     *
     * The statement is either:
     *    (A → C and B → D)  or  (B → C and A → D)
     *
     * The secret switchFlag (0 or 1) determines which branch is real.
     * The real branch is generated using witness values rC and rD.
     * The simulated branch is generated using simulation with a single fake challenge.
     *
     * The global challenge e is computed by concatenating all 4 commitments.
     * Then, the branch challenges are set such that:
     *    e = cReal + cFake,
     * where cReal is used for the real branch and cFake for the simulated branch.
     */
    fun generateOrProof(
        a1: GroupElement, a2: GroupElement,
        b1: GroupElement, b2: GroupElement,
        c1: GroupElement, c2: GroupElement,
        d1: GroupElement, d2: GroupElement,
        rC: BigInteger,
        rD: BigInteger,
        switchFlag: Int,  // 0 or 1; remains secret to the prover.
        publicKey: PublicKey,
        domainParameters: ECDomainParameters
    ): ZKPOrProof {
        require(switchFlag == 0 || switchFlag == 1)

        // Organize parameters into helper tuples.
        val real1Params: FiveTuple
        val real2Params: FiveTuple
        val fake1Params: FourTuple
        val fake2Params: FourTuple

        println("Prover: switchFlag = $switchFlag\n")
        if (switchFlag == 0) {
            // Real branch: (A → C, B → D)
            real1Params = FiveTuple(a1, a2, c1, c2, rC)
            real2Params = FiveTuple(b1, b2, d1, d2, rD)
            // Simulated branch: (B → C, A → D)
            fake1Params = FourTuple(b1, b2, c1, c2)
            fake2Params = FourTuple(a1, a2, d1, d2)
        } else {
            // Real branch: (B → C, A → D)
            real1Params = FiveTuple(b1, b2, c1, c2, rC)
            real2Params = FiveTuple(a1, a2, d1, d2, rD)
            // Simulated branch: (A → C, B → D)
            fake1Params = FourTuple(a1, a2, c1, c2)
            fake2Params = FourTuple(b1, b2, d1, d2)
        }

        // 1) Compute real branch commitments.
        val realCommit1 = commitRealSubProof(publicKey, domainParameters)
        val realCommit2 = commitRealSubProof(publicKey, domainParameters)

        // 2) For the fake branch, generate ONE fake challenge value.
        val rnd = SecureRandom.getInstanceStrong()
        val fakeChallenge = BigIntegerUtils.randomBigInteger(domainParameters.n, rnd)
        // Use the same fakeChallenge for both simulated sub‑proofs.
        val fakeCommit1 = simulateFakeSubProofWithGivenChallenge(
            fake1Params.a1, fake1Params.a2, fake1Params.c1, fake1Params.c2,
            fakeChallenge, publicKey, domainParameters
        )
        val fakeCommit2 = simulateFakeSubProofWithGivenChallenge(
            fake2Params.a1, fake2Params.a2, fake2Params.c1, fake2Params.c2,
            fakeChallenge, publicKey, domainParameters
        )

        // 3) Compute the global challenge e by concatenating all commitments.
        val baos = ByteArrayOutputStream()
        fun putCommit(A_g: GroupElement, A_h: GroupElement) {
            baos.write(A_g.data.toByteArray())
            baos.write(A_h.data.toByteArray())
        }

        if (switchFlag == 0){
            // The first proof is related to upper output
            putCommit(realCommit1.A_g, realCommit1.A_h)
            putCommit(realCommit2.A_g, realCommit2.A_h)
            putCommit(fakeCommit1.A_g, fakeCommit1.A_h)
            putCommit(fakeCommit2.A_g, fakeCommit2.A_h)
        }
        else {
            putCommit(fakeCommit1.A_g, fakeCommit1.A_h)
            putCommit(fakeCommit2.A_g, fakeCommit2.A_h)
            putCommit(realCommit1.A_g, realCommit1.A_h)
            putCommit(realCommit2.A_g, realCommit2.A_h)
        }

        val eBytes = baos.toByteArray()
        val e = CryptoUtils.hashToBigInteger(eBytes).mod(domainParameters.n)
//        println("Prover: Global challenge input bytes: ${eBytes.joinToString("") { "%02x".format(it) }}")
//        println("Prover: Computed global challenge (e): ${e.toString(16)}\n")

        // 4) Since the simulated branch used the same fakeChallenge in both sub-proofs,
        // we set the fake branch challenge to that value.
        val cFake = fakeChallenge
        // Set real branch challenge as: cReal = e - cFake (mod n)
        val cReal = e.subtract(cFake).mod(domainParameters.n)
//        println("Prover: Real branch challenge (cReal): ${cReal.toString(16)}")
//        println("Prover: Fake branch challenge: ${cFake.toString(16)}\n")

        // 5) Finalize the real branch sub‑proofs using challenge cReal.
        val proofReal1 = finalizeRealSubProof(realCommit1, cReal, real1Params.r, domainParameters)
        val proofReal2 = finalizeRealSubProof(realCommit2, cReal, real2Params.r, domainParameters)

        // 6) The fake branch proofs are taken directly from simulation.
        val proofFake1 = SchnorrProofDL(fakeCommit1.A_g, fakeCommit1.A_h, fakeCommit1.zFake)
        val proofFake2 = SchnorrProofDL(fakeCommit2.A_g, fakeCommit2.A_h, fakeCommit2.zFake)

        val realAnd = ZKPAndProof(proofReal1, proofReal2)
        val fakeAnd = ZKPAndProof(proofFake1, proofFake2)

        // The transcript: branchChallengeA = cReal, branchChallengeB = cFake,
        // fullChallenge = e.
        val (challengeA, challengeB, proofA, proofB) =
            if (switchFlag == 0)
                // The first proof is related to upper output
                Quadruple(cReal, cFake, realAnd, fakeAnd)
            else
                Quadruple(cFake, cReal, fakeAnd, realAnd)

        return ZKPOrProof(
            proofA = proofA,
            proofB = proofB,
            challengeA = challengeA,
            challengeB = challengeB,
            fullChallenge = e
        )
    }

    /**
     * Simulates a Schnorr sub‑proof for the fake branch using a provided fake challenge.
     *
     * Given input ciphertexts (a1,a2) and (c1,c2) (from which one computes X = c1 - a1 and Y = c2 - a2),
     * this function uses the externally supplied fakeChallenge (which is the same for both simulated sub‑proofs)
     * and a random fake response zFake to compute the fake commitments as:
     *
     *    A_g = g^(zFake) - X * (fakeChallenge)
     *    A_h = h^(zFake) - Y * (fakeChallenge)
     *
     * The fake challenge is not chosen randomly here; it is provided by the caller.
     */
    private fun simulateFakeSubProofWithGivenChallenge(
        a1: GroupElement,
        a2: GroupElement,
        c1: GroupElement,
        c2: GroupElement,
        fakeChallenge: BigInteger, // externally provided, same for both sub‑proofs
        publicKey: PublicKey,
        domainParameters: ECDomainParameters
    ): SchnorrCommitFake {
        val rnd = SecureRandom.getInstanceStrong()

        // Deserialize input points.
        val a1Point = CryptoUtils.deserializeGroupElement(a1, domainParameters)
        val a2Point = CryptoUtils.deserializeGroupElement(a2, domainParameters)
        val c1Point = CryptoUtils.deserializeGroupElement(c1, domainParameters)
        val c2Point = CryptoUtils.deserializeGroupElement(c2, domainParameters)
        val hPoint  = CryptoUtils.extractECPointFromPublicKey(publicKey)
        // Compute X and Y (the statement elements).
        val XPoint = c1Point.add(a1Point.negate()).normalize()
        val YPoint = c2Point.add(a2Point.negate()).normalize()

        // Choose a random fake response.
        val zFake = BigIntegerUtils.randomBigInteger(domainParameters.n, rnd)

        // Compute fake commitments:
        //   A_g = g^(zFake) - X * fakeChallenge
        //   A_h = h^(zFake) - Y * fakeChallenge
        val A_gPoint = domainParameters.g.multiply(zFake)
            .subtract(XPoint.multiply(fakeChallenge)).normalize()
        val A_hPoint = hPoint.multiply(zFake)
            .subtract(YPoint.multiply(fakeChallenge)).normalize()

//        println("A_gPoint: ${A_gPoint}")
//        println("g: ${domainParameters.g}")
//        println("zFake: ${zFake}")
//        println("fakeChallenge: ${fakeChallenge}")
//        println("XPoint: ${XPoint}")
//        println("c1Point: ${c1Point}")
//        println("a1Point: ${a1Point}\n")

        return SchnorrCommitFake(
            A_g = CryptoUtils.serializeGroupElement(A_gPoint),
            A_h = CryptoUtils.serializeGroupElement(A_hPoint),
            cFake = fakeChallenge, // record the provided fake challenge
            zFake = zFake
        )
    }

    /**
     * Computes a real commitment for a sub‑proof:
     *    A_g = g^t  and  A_h = h^t,
     * where t is chosen randomly.
     */
    private fun commitRealSubProof(
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
            t = t
        )
    }

    /**
     * Finalizes a real sub‑proof by computing the response:
     *    z = t + (challengeReal * r) mod n,
     * where r is the secret witness.
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
            z = z
        )
    }
}

/*
 * Helper data classes.
 */
private data class Quadruple<A, B, C, D>(
    val first: A,    // Branch challenge for branch A (real branch)
    val second: B,   // Branch challenge for branch B (simulated branch)
    val third: C,    // AND-proof for branch A
    val fourth: D    // AND-proof for branch B
)

private data class FiveTuple(
    val a1: GroupElement,
    val a2: GroupElement,
    val c1: GroupElement,
    val c2: GroupElement,
    val r: BigInteger
)

private data class FourTuple(
    val a1: GroupElement,
    val a2: GroupElement,
    val c1: GroupElement,
    val c2: GroupElement
)
