package org.example.mixnet

import meerkat.protobuf.ConcreteCrypto.GroupElement
import java.math.BigInteger

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