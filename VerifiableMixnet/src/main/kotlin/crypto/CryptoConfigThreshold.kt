package org.example.crypto

import meerkat.protobuf.ConcreteCrypto
import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import org.example.mixnet.SchnorrProofDL
import org.example.mixnet.ZKPUtils
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * Data class representing the overall threshold decryption result.
 * It contains the decrypted message as well as a list of (serverId, SchnorrProofDL) pairs.
 */
data class ThresholdDecryptionResult(
    val message: String,
    val proofs: List<Pair<Int, SchnorrProofDL>>
)

/**
 * ThresholdCryptoConfig provides threshold key generation and decryption (with attached proofs)
 * in a "t-out-of-n" scheme. Its constants and lazy‑loading style follow that of CryptoConfig.
 */
object ThresholdCryptoConfig {

    // Constants matching CryptoConfig.
    private const val EC_CURVE_NAME = "secp256r1"
    private const val MIN_KEY_SIZE = 256
    private const val MAX_KEY_SIZE = 521

    /**
     * Lazy-loaded EC domain parameters.
     */
    val ecDomainParameters: ECDomainParameters by lazy {
        val ecParams: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE_NAME)
            ?: throw IllegalArgumentException("Curve $EC_CURVE_NAME not found")
        ECDomainParameters(
            ecParams.curve,
            ecParams.g,
            ecParams.n,
            ecParams.h,
            ecParams.seed
        )
    }

    /**
     * Converts an ECPoint to a PublicKey.
     */
    fun ecPointToPublicKey(point: ECPoint): ECPublicKey {
        val ecSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE_NAME)
        val pubSpec = org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec)
        val keyFactory = KeyFactory.getInstance("EC", "BC")
        return keyFactory.generatePublic(pubSpec) as ECPublicKey
    }

    // --- Internal classes and helper methods for share distribution and decryption ---

    /**
     * Message used for inter-thread communication.
     */
    data class ShareMessage(val fromId: Int, val share: BigInteger)

    /**
     * Each ThresholdServer runs in its own thread.
     * It generates a random polynomial (of degree t-1) and computes one share for each destination.
     * After sending its shares via its BlockingQueue (the inter-thread “pipe”), it waits to receive
     * n shares, computes its secret share, and then discards its temporary data.
     */
    class ThresholdServer(
        private val id: Int,           // Server identifier (1-indexed)
        private val n: Int,            // Total number of servers
        val t: Int,            // Threshold value
        private val commMap: Map<Int, BlockingQueue<ShareMessage>>,
        private val random: SecureRandom // Provided random instance
    ) : Runnable {

        private val order: BigInteger = ecDomainParameters.n
        // Use the provided random instance instead of creating a new one.
        // Temporary polynomial and outgoing shares; these are destroyed after share distribution.
        private var polynomial: List<BigInteger>? = generatePolynomial(t - 1)
        private var outgoingShares: Map<Int, BigInteger>? = (1..n).associate { x ->
            x to evaluatePolynomial(polynomial!!, BigInteger.valueOf(x.toLong()))
        }

        // Each server’s private incoming communication channel.
        private val incomingQueue: BlockingQueue<ShareMessage> = commMap[id]!!

        // The computed secret share S = F(id).
        // (Kept private – only used to generate the decryption share and ZKP.)
        internal var secretShare: BigInteger? = null
            private set

        // This will be set after we compute the secretShare.
        var partialPublicKey: ECPoint? = null
            private set

        override fun run() {
            // Send each share to its destination.
            outgoingShares?.forEach { (destId, share) ->
                commMap[destId]?.put(ShareMessage(id, share))
            }
            // Destroy temporary data.
            polynomial = null
            outgoingShares = null

            // Wait to receive exactly n share messages (including self-share).
            val receivedShares = mutableListOf<BigInteger>()
            repeat(n) {
                val msg = incomingQueue.take()
                receivedShares.add(msg.share)
            }
            // Compute secret share: S = sum(receivedShares) mod order.
            secretShare = receivedShares.fold(BigInteger.ZERO) { acc, s -> acc.add(s).mod(order) }

            // Now set partialPublicKey = g^{s_i}
            partialPublicKey = ecDomainParameters.g.multiply(secretShare).normalize()
        }

        /**
         * Computes the partial decryption: d_i = c1^{s_i}.
         */
        fun computePartialDecryption(c1: ECPoint): ECPoint {
            val s = secretShare ?: throw IllegalStateException("Secret share not computed for server $id")
            return c1.multiply(s).normalize()
        }

        /**
         * Returns the partial public key: h_i = g^{s_i}.
         */
        fun getPartialPublickey(): ECPoint {
            return partialPublicKey
                ?: throw IllegalStateException("Partial public key not initialized for server $id")
        }

        fun getId(): Int = id

        /**
         * Generates a Schnorr ZKP proving that the decryption share d_i = c1^{s_i} was computed using
         * the same secret share s_i that yields h_i = g^{s_i}.
         *
         * It proves knowledge of s_i such that:
         *      h_i = g^{s_i}   and   d_i = c1^{s_i}.
         *
         * This uses a Fiat–Shamir transformation over the commitments.
         */
        fun generateDecryptionProof(c1: ECPoint): SchnorrProofDL {
            val s = secretShare ?: throw IllegalStateException("Secret share not computed for server $id")
            // h_i = g^{s_i} (server's public share)
            val h_i = getPartialPublickey()
            // Convert c1 to a PublicKey so that commitRealSubProof uses c1 as the second base.
            val c1AsPublicKey = ecPointToPublicKey(c1)
            // Commit: choose a random t and compute commitments.
            val commit = ZKPUtils.commitRealSubProof(c1AsPublicKey, ecDomainParameters, random)
            // Compute the decryption share d_i = c1^{s_i}.
            val d_i = c1.multiply(s).normalize()

            // Build a ByteArrayOutputStream to accumulate all the bytes.
            val baos = java.io.ByteArrayOutputStream()
            fun putCommit(A_g: ConcreteCrypto.GroupElement, A_h: ConcreteCrypto.GroupElement) {
                baos.write(A_g.data.toByteArray())
                baos.write(A_h.data.toByteArray())
            }
            // Write the commitments.
            putCommit(commit.A_g, commit.A_h)
            // Write the serialized public share and decryption share.
            baos.write(CryptoUtils.serializeGroupElement(h_i).data.toByteArray())
            baos.write(CryptoUtils.serializeGroupElement(d_i).data.toByteArray())
            // Compute the challenge from the concatenated bytes.
            val challenge = CryptoUtils.hashToBigInteger(baos.toByteArray())

            // Finalize and return the Schnorr proof.
            return ZKPUtils.finalizeRealSubProof(commit, challenge, s, ecDomainParameters)
        }


        private fun generatePolynomial(degree: Int): List<BigInteger> =
            List(degree + 1) { BigIntegerUtils.randomBigInteger(order, random) }

        private fun evaluatePolynomial(poly: List<BigInteger>, x: BigInteger): BigInteger {
            var result = BigInteger.ZERO
            var xPower = BigInteger.ONE
            for (coeff in poly) {
                result = result.add(coeff.multiply(xPower)).mod(order)
                xPower = xPower.multiply(x).mod(order)
            }
            return result
        }
    }

    /**
     * Combines partial decryptions (pairs of server id and partial ECPoint) using Lagrange interpolation.
     */
    private fun combinePartialDecryptions(
        partials: List<Pair<Int, ECPoint>>,
        domainParameters: ECDomainParameters
    ): ECPoint {
        val indices = partials.map { it.first }
        var combined: ECPoint = domainParameters.g.curve.infinity
        partials.forEach { (id, partial) ->
            val coeff = lagrangeCoefficient(id, indices, domainParameters.n)
            combined = combined.add(partial.multiply(coeff)).normalize()
        }
        return combined
    }

    /**
     * Computes the Lagrange coefficient for index i at x = 0 given all indices.
     */
    private fun lagrangeCoefficient(i: Int, indices: List<Int>, modulus: BigInteger): BigInteger {
        var num = BigInteger.ONE
        var den = BigInteger.ONE
        val xi = BigInteger.valueOf(i.toLong())
        indices.forEach { j ->
            if (j != i) {
                val xj = BigInteger.valueOf(j.toLong())
                num = num.multiply(xj.negate()).mod(modulus)
                den = den.multiply(xi.subtract(xj)).mod(modulus)
            }
        }
        return num.multiply(den.modInverse(modulus)).mod(modulus)
    }

    // --- Public API ---

    /**
     * Generates threshold key shares using n servers with threshold t.
     *
     * Internally, this creates inter-thread communication channels, instantiates n ThresholdServer threads,
     * starts them, and then reconstructs the overall public key Q = F(0)*G via Lagrange interpolation.
     *
     * @param n Total number of servers.
     * @param t Threshold (minimum number of servers needed for decryption).
     * @param random A SecureRandom instance provided by the caller.
     * @return Pair of overall PublicKey and list of ThresholdServer instances.
     */
    fun generateThresholdKeyPair(n: Int, t: Int, random: SecureRandom): Pair<ECPublicKey, List<ThresholdServer>> {
        // Create inter-thread communication channels (one BlockingQueue per server).
        val commMap: Map<Int, BlockingQueue<ShareMessage>> =
            (1..n).associateWith { LinkedBlockingQueue<ShareMessage>() }

        // Instantiate servers, each receiving the same random instance.
        val servers = (1..n).map { id ->
            ThresholdServer(id, n, t, commMap, random)
        }
        // Start each server in its own thread.
        val threads = servers.map { server ->
            Thread(server).apply { start() }
        }
        threads.forEach { it.join() }

        // Reconstruct overall public key Q = F(0)*G via Lagrange interpolation using all n shares.
        val indices = (1..n).toList()
        var overallPublicKeyPoint: ECPoint = ecDomainParameters.g.curve.infinity
        servers.forEach { server ->
            val coeff = lagrangeCoefficient(server.getId(), indices, ecDomainParameters.n)
            overallPublicKeyPoint =
                overallPublicKeyPoint.add(server.getPartialPublickey().multiply(coeff)).normalize()
        }
        return Pair(ecPointToPublicKey(overallPublicKeyPoint), servers)
    }

    /**
     * Performs threshold decryption on a RerandomizableEncryptedMessage.
     *
     * Given a ciphertext c = (c1, c2) where c1 = k*G and c2 = M + k*Q,
     * a subset (of at least t servers) computes partial decryptions d_i = c1^{s_i}.
     * These partials are combined via Lagrange interpolation to compute D = k*F(0)*G,
     * and then the message is recovered as M = c2 - D.
     *
     * In addition, for each participating server a Schnorr proof is generated showing that
     * the decryption share was computed correctly.
     * We also verify each proof before combining partial decryptions.
     *
     *
     * @param encryptedMessage The ciphertext.
     * @param participatingServers The list of servers (must be at least t in number) participating in decryption.
     * @return A ThresholdDecryptionResult containing the decrypted message and the proofs.
     */
    fun thresholdDecrypt(
        encryptedMessage: RerandomizableEncryptedMessage,
        participatingServers: List<ThresholdServer>
    ): ThresholdDecryptionResult {
        val ciphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)
        val c1 = CryptoUtils.deserializeGroupElement(ciphertext.c1, ecDomainParameters)
        val c2 = CryptoUtils.deserializeGroupElement(ciphertext.c2, ecDomainParameters)

        // Each participating server computes partial decryption + proof
        val partialsWithProofs = participatingServers.map { server ->
            val d_i = server.computePartialDecryption(c1)
            val proof_i = server.generateDecryptionProof(c1)
            // Verify the proof immediately
            val partialPubKey = server.partialPublicKey
                ?: throw IllegalStateException("No partial public key for server ${server.getId()}")

            val isValid = verifyDecryptionProof(partialPubKey, c1, d_i, proof_i)
            // Return everything in a single triple
            Triple(server.getId(), d_i, if (isValid) proof_i else null)
        }

        // Filter out any partials whose proof failed
        val validPartials = partialsWithProofs.filter { it.third != null }

        // If not enough partials are valid, we can't decrypt fully
        if (validPartials.size < participatingServers[0].t) {
            throw IllegalStateException("Not enough valid partial decryptions to meet threshold.")
        }

        // Combine only valid partial decryptions
        val partialDecryptions = validPartials.map { Pair(it.first, it.second) }
        val decryptionFactor = combinePartialDecryptions(partialDecryptions, ecDomainParameters)
        val mPoint = c2.subtract(decryptionFactor).normalize()
        val message = MessageUtils.decodeECPointToMessage(mPoint)

        // For the final result, collect only the proofs that were valid
        val finalProofs = validPartials.map { Pair(it.first, it.third!!) }

        return ThresholdDecryptionResult(message, finalProofs)
    }

    fun verifyDecryptionProof(
        partialPublicKey: ECPoint,
        c1: ECPoint,
        d_i: ECPoint,
        proof: SchnorrProofDL
    ): Boolean {
        // Rebuild the challenge from the same info used in generateDecryptionProof
        val baos = java.io.ByteArrayOutputStream()

        // The commit points A_g, A_h are in proof.A_g, proof.A_h
        baos.write(proof.A_g.data.toByteArray())
        baos.write(proof.A_h.data.toByteArray())

        // partialPublicKey is h_i, d_i is c1^{s_i}
        baos.write(CryptoUtils.serializeGroupElement(partialPublicKey).data.toByteArray())
        baos.write(CryptoUtils.serializeGroupElement(d_i).data.toByteArray())

        val challenge = CryptoUtils.hashToBigInteger(baos.toByteArray())

        // Now check the Schnorr conditions:
        // For the "g" base:
        //   G^z == A_g + h_i^challenge
        // For the "c1" base:
        //   c1^z == A_h + d_i^challenge
        // We'll do something similar to how finalize is checked.

        // We'll create the left and right sides for each base.
        val z = proof.z

        // Left side for base G
        val lhsG = ecDomainParameters.g.multiply(z).normalize()
        // Right side for base G
        val A_gPoint = CryptoUtils.deserializeGroupElement(proof.A_g, ecDomainParameters)
        val rightG = A_gPoint.add(partialPublicKey.multiply(challenge)).normalize()

        if (!lhsG.equals(rightG)) {
            return false
        }

        // Left side for base c1
        val lhsC1 = c1.multiply(z).normalize()
        // Right side for base c1
        val A_hPoint = CryptoUtils.deserializeGroupElement(proof.A_h, ecDomainParameters)
        val rightC1 = A_hPoint.add(d_i.multiply(challenge)).normalize()

        if (!lhsC1.equals(rightC1)) {
            return false
        }

        return true
    }
}
