package org.example.crypto

import meerkat.protobuf.ConcreteCrypto.ElGamalCiphertext
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import java.math.BigInteger
import java.security.SecureRandom
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint

// Data class for inter-thread share messages.
data class ShareMessage(val fromId: Int, val share: BigInteger)

/**
 * Each ThresholdServer runs in its own thread.
 * It generates a random polynomial (and its evaluated matrix of shares),
 * sends one share per destination via its private communication pipe,
 * receives shares from all other servers, computes its secret key share,
 * and then destroys its temporary matrix data.
 */
class ThresholdServer(
    private val id: Int,           // Server id (1-indexed)
    private val n: Int,            // Total number of servers
    private val t: Int,            // Threshold value
    private val domainParameters: ECDomainParameters,
    // Communication channel: mapping from server id to its BlockingQueue.
    private val commMap: Map<Int, BlockingQueue<ShareMessage>>
) : Runnable {

    private val order: BigInteger = domainParameters.n
    private val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()

    // These variables hold the temporary secret matrix and are destroyed after use.
    private var polynomial: List<BigInteger>? = generatePolynomial(t - 1)
    private var outgoingShares: Map<Int, BigInteger>? = (1..n).associate { x ->
        x to evaluatePolynomial(polynomial!!, BigInteger.valueOf(x.toLong()))
    }

    // Each server's private incoming queue.
    private val incomingQueue: BlockingQueue<ShareMessage> = commMap[id]!!

    // The secret share computed from all received shares.
    private var secretShare: BigInteger? = null

    override fun run() {
        // Send each share to its destination using inter-thread communication.
        outgoingShares?.forEach { (destId, share) ->
            commMap[destId]?.put(ShareMessage(id, share))
        }
        // Destroy temporary matrix data.
        polynomial = null
        outgoingShares = null

        // Expect exactly n share messages (including self-share).
        val receivedShares = mutableListOf<BigInteger>()
        repeat(n) {
            val msg = incomingQueue.take()
            receivedShares.add(msg.share)
        }
        // Compute secret share: S_i = sum(receivedShares) mod order.
        secretShare = receivedShares.fold(BigInteger.ZERO) { acc, s -> acc.add(s).mod(order) }
    }

    // Computes the partial decryption: d_i = S_i * c1.
    fun computePartialDecryption(c1: ECPoint): ECPoint {
        val s = secretShare ?: throw IllegalStateException("Server $id: secret share not computed")
        return c1.multiply(s).normalize()
    }

    // Returns the partial public key: h_i = S_i * G.
    fun getPartialPublicKey(): ECPoint {
        val s = secretShare ?: throw IllegalStateException("Server $id: secret share not computed")
        return domainParameters.g.multiply(s).normalize()
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
 * ThresholdCoordinator orchestrates the threshold key generation and decryption.
 * It creates servers with private communication channels (pipes), initiates share distribution,
 * and later collects partial decryptions to perform threshold decryption.
 */
object ThresholdCoordinator {

    /**
     * Sets up threshold key generation.
     *
     * 1. Creates a communication map (server id → BlockingQueue).
     * 2. Instantiates n ThresholdServer threads.
     * 3. Starts all threads to perform share distribution and secret share computation.
     * 4. Collects each server’s partial public key and computes the overall public key Q = G^(∑S_i)
     *    by adding the partial public keys.
     *
     * @return Pair of overall public key Q and the list of servers.
     */
    fun setupThresholdKeyGeneration(
        n: Int,
        t: Int,
        domainParameters: ECDomainParameters
    ): Pair<ECPoint, List<ThresholdServer>> {
        // Create communication channels (one BlockingQueue per server).
        val commMap: Map<Int, BlockingQueue<ShareMessage>> =
            (1..n).associateWith { LinkedBlockingQueue<ShareMessage>() }

        // Instantiate servers.
        val servers = (1..n).map { id ->
            ThresholdServer(id, n, t, domainParameters, commMap)
        }
        // Start each server in its own thread.
        val threads = servers.map { server ->
            Thread(server).apply { start() }
        }
        // Wait for all servers to finish.
        threads.forEach { it.join() }

        // Compute overall public key: Q = ∑ (S_i * G).
        val overallPublicKey = servers.map { it.getPartialPublicKey() }
            .reduce { acc, pubKey -> acc.add(pubKey).normalize() }
        return Pair(overallPublicKey, servers)
    }

    /**
     * Performs threshold decryption.
     *
     * Given an encrypted message (RerandomizableEncryptedMessage) where
     * ciphertext c = (c1, c2) = (k*G, M + k*Q), a subset (at least t) of servers compute
     * their partial decryption d_i = S_i * c1. Using Lagrange interpolation on these partials,
     * the coordinator reconstructs D = Σ λ_i * d_i and recovers M = c2 - D.
     *
     * @param encryptedMessage The rerandomizable encrypted message.
     * @param participatingServers The list of servers (at least t) participating in decryption.
     * @param domainParameters The EC domain parameters.
     * @return The decrypted message as a String.
     */
    fun thresholdDecrypt(
        encryptedMessage: RerandomizableEncryptedMessage,
        participatingServers: List<ThresholdServer>,
        domainParameters: ECDomainParameters
    ): String {
        val ciphertext = CryptoUtils.unwrapCiphertext(encryptedMessage)
        val c1 = CryptoUtils.deserializeGroupElement(ciphertext.c1, domainParameters)
        val c2 = CryptoUtils.deserializeGroupElement(ciphertext.c2, domainParameters)

        // Each participating server computes its partial decryption.
        val partialDecryptions = participatingServers.map { server ->
            Pair(server.getId(), server.computePartialDecryption(c1))
        }
        // Combine partial decryptions via Lagrange interpolation.
        val decryptionFactor = combinePartialDecryptions(partialDecryptions, domainParameters)
        // Recover message: M = c2 - D.
        val mPoint = c2.subtract(decryptionFactor).normalize()
        return MessageUtils.decodeECPointToMessage(mPoint)
    }

    // Helper: Combines partial decryptions using Lagrange interpolation.
    private fun combinePartialDecryptions(
        partials: List<Pair<Int, ECPoint>>,
        domainParameters: ECDomainParameters
    ): ECPoint {
        fun lagrangeCoefficient(i: Int, indices: List<Int>): BigInteger {
            val order = domainParameters.n
            var num = BigInteger.ONE
            var den = BigInteger.ONE
            val xi = BigInteger.valueOf(i.toLong())
            for (j in indices) {
                if (j == i) continue
                val xj = BigInteger.valueOf(j.toLong())
                num = num.multiply(xj.negate()).mod(order)
                den = den.multiply(xi.subtract(xj)).mod(order)
            }
            return num.multiply(den.modInverse(order)).mod(order)
        }
        val indices = partials.map { it.first }
        var combined: ECPoint = domainParameters.g.curve.infinity
        for ((id, partial) in partials) {
            val coeff = lagrangeCoefficient(id, indices)
            combined = combined.add(partial.multiply(coeff)).normalize()
        }
        return combined
    }
}
