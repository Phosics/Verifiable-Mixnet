package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.PublicKey
import org.bouncycastle.crypto.params.ECDomainParameters
import org.example.crypto.CryptoUtils
import org.example.crypto.BigIntegerUtils
import java.security.SecureRandom

/**
 * Represents a Schnorr Discrete-Log-Equality Proof for a single pair.
 */
data class SchnorrProofDL(
    val A_g: GroupElement, // Commitment A_g = g^t
    val A_h: GroupElement, // Commitment A_h = h^t
    val z: BigInteger      // Response z = t + c * r mod q
)

/**
 * Encapsulates the Schnorr proofs for both swapped outputs.
 */
data class ZKPAndProof(
    val proof1: SchnorrProofDL,
    val proof2: SchnorrProofDL
)

data class SimulatedProofDL(
    val A_g: GroupElement,
    val A_h: GroupElement,
    val z: BigInteger,
    val cSim: BigInteger
)

data class ZKPOrProof(
    val proofA: ZKPAndProof,     // The "A" side (two subproofs in AND)
    val proofB: ZKPAndProof,     // The "B" side
    val challengeA: BigInteger,  // eA
    val challengeB: BigInteger,  // eB
    val fullChallenge: BigInteger
)

