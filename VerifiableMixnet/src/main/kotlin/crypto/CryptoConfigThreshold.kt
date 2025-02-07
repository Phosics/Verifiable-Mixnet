package org.example.crypto

import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * ThresholdCryptoConfig provides threshold key generation and decryption in a
 * "t-out-of-n" scheme. It follows the same style as CryptoConfig.
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
    fun ecPointToPublicKey(point: ECPoint): PublicKey {
        val ecSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE_NAME)
        val pubSpec = org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec)
        val keyFactory = KeyFactory.getInstance("EC", "BC")
        return keyFactory.generatePublic(pubSpec)
    }

    // --- Internal classes and helper methods ---

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
        private val t: Int,            // Threshold value
        private val commMap: Map<Int, BlockingQueue<ShareMessage>>
    ) : Runnable {

        private val order: BigInteger = ecDomainParameters.n
        private val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()

        // Temporary polynomial and outgoing shares; these are destroyed after share distribution.
        private var polynomial: List<BigInteger>? = generatePolynomial(t - 1)
        private var outgoingShares: Map<Int, BigInteger>? = (1..n).associate { x ->
            x to evaluatePolynomial(polynomial!!, BigInteger.valueOf(x.toLong()))
        }

        // Each server’s private incoming communication channel.
        private val incomingQueue: BlockingQueue<ShareMessage> = commMap[id]!!

        // The computed secret share S = F(id).
        private var secretShare: BigInteger? = null

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
        }

        /**
         * Computes the partial decryption: d_i = S * c1.
         */
        fun computePartialDecryption(c1: ECPoint): ECPoint {
            val s = secretShare ?: throw IllegalStateException("Server $id: secret share not computed")
            return c1.multiply(s).normalize()
        }

        /**
         * Returns the partial public key: h_i = S * G.
         */
        fun getPartialPublicKey(): ECPoint {
            val s = secretShare ?: throw IllegalStateException("Server $id: secret share not computed")
            return ecDomainParameters.g.multiply(s).normalize()
        }

        fun getId(): Int = id

        private fun generatePolynomial(degree: Int): List<BigInteger> =
            List(degree + 1) { BigIntegerUtils.randomBigInteger(order, secureRandom) }

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
     * Internally, this creates inter-thread communication channels, instantiates n ThresholdServer threads,
     * starts them, and then reconstructs the overall public key Q = F(0)*G via Lagrange interpolation.
     *
     * @param n Total number of servers.
     * @param t Threshold (minimum number of servers needed for decryption).
     * @return Pair of overall PublicKey and list of ThresholdServer instances.
     */
    fun generateThresholdKeyPair(n: Int, t: Int): Pair<PublicKey, List<ThresholdServer>> {
        // Create inter-thread communication channels (one BlockingQueue per server).
        val commMap: Map<Int, BlockingQueue<ShareMessage>> =
            (1..n).associateWith { LinkedBlockingQueue<ShareMessage>() }

        // Instantiate servers.
        val servers = (1..n).map { id ->
            ThresholdServer(id, n, t, commMap)
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
            overallPublicKeyPoint = overallPublicKeyPoint.add(server.getPartialPublicKey().multiply(coeff)).normalize()
        }
        return Pair(ecPointToPublicKey(overallPublicKeyPoint), servers)
    }

    /**
     * Performs threshold decryption on a RerandomizableEncryptedMessage.
     *
     * Given a ciphertext c = (c1, c2) where c1 = k*G and c2 = M + k*Q,
     * a subset (of at least t servers) computes partial decryptions d_i = S_i * c1.
     * These partials are combined via Lagrange interpolation to compute D = k*F(0)*G,
     * and then the message is recovered as M = c2 - D.
     *
     * @param encryptedMessage The ciphertext.
     * @param participatingServers The list of servers (must be at least t in number) participating in decryption.
     * @return The decrypted message as a String.
     */
    fun thresholdDecrypt(
        encryptedMessage: RerandomizableEncryptedMessage,
        participatingServers: List<ThresholdServer>
    ): String {
        val ciphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)
        val c1 = CryptoUtils.deserializeGroupElement(ciphertext.c1, ecDomainParameters)
        val c2 = CryptoUtils.deserializeGroupElement(ciphertext.c2, ecDomainParameters)

        // Each participating server computes its partial decryption.
        val partialDecryptions = participatingServers.map { server ->
            Pair(server.getId(), server.computePartialDecryption(c1))
        }
        val decryptionFactor = combinePartialDecryptions(partialDecryptions, ecDomainParameters)
        val mPoint = c2.subtract(decryptionFactor).normalize()
        return MessageUtils.decodeECPointToMessage(mPoint)
    }
}
