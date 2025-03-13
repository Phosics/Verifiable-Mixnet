package mixnet

import bulltinboard.BulletinBoard
import kotlinx.coroutines.*
import org.apache.logging.log4j.LogManager
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.security.PublicKey
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory

/**
 * Manages multiple MixServer instances to imitate a mixnet.
 *
 * @param t The number of adversaries. The total number of servers is 2t + 1.
 * @param n The number of votes to be mixed. Must be a power of 2.
 */
class MixServersManager(
    private val publicKey: PublicKey,
    private val domainParameters: ECDomainParameters,
    private val t: Int,
    private val bulletinBoard: BulletinBoard,
    private val pollID: String
) {
    private val n = bulletinBoard.numberOfVotes
    private val numServers = t + 1
    private val logger = LogManager.getLogger(MixServersManager::class.java)

    private val mixServers: List<MixServer>
    private val serverScopes: List<CoroutineScope>

    init {
        require(t > -1) { "Number of adversaries t must be positive" }
        require(n > 0 && (n and (n - 1)) == 0) { "n must be a power of 2" }

        // Initialize 2t + 1 MixServer instances
        mixServers = List(numServers) { index ->
            logger.info("Initializing MixServer ${index + 1}/$numServers with n=$n")
            MixServer(domainParameters, publicKey, index, bulletinBoard, pollID)
        }

        // Create a CoroutineScope for each MixServer with a dedicated dispatcher
        serverScopes = mixServers.map { mixServer ->
            val threadName = "MixServer-${mixServer.getIndex() + 1}"
            val dispatcher: CoroutineDispatcher = createSingleThreadDispatcher(threadName)
            CoroutineScope(dispatcher)
        }
    }

    fun getAmountOfServers() : Int {
        return numServers
    }

    fun runServers() : List<Job> {
        return mixServers.mapIndexed { index, mixServer ->
            val scope = serverScopes[index]
            scope.launch {
                mixServer.run()
            }
        }
    }

    /**
     * Creates a single-threaded CoroutineDispatcher with a custom thread name.
     *
     * @param threadName The desired name for the thread.
     * @return A CoroutineDispatcher backed by a single thread with the specified name.
     */
    private fun createSingleThreadDispatcher(threadName: String): CoroutineDispatcher {
        val threadFactory = object : ThreadFactory {
            override fun newThread(r: Runnable): Thread {
                return Thread(r, threadName).apply {
                    isDaemon = true // Set to true if you want daemon threads
                }
            }
        }
        val executor = Executors.newSingleThreadExecutor(threadFactory)
        return executor.asCoroutineDispatcher()
    }

    /**
     * Retrieves the public keys of all MixServers.
     *
     * @return A map of MixServer indices to their respective public keys.
     */
    fun getAllPublicKeys(): Map<String, Ed25519PublicKeyParameters> {
        return mixServers.associate { it.getIndex().toString() to it.ed25519PublicKey }
    }

}