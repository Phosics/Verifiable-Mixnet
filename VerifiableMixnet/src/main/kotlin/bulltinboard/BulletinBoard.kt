package bulltinboard

import com.google.protobuf.AbstractMessage
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import crypto.CryptoUtils
import mixnet.MixBatchOutput
import mixnet.Vote
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.util.*
import kotlin.math.ceil
import kotlin.math.log2
import kotlin.math.pow

const val TIMEOUT = 5000

/**
 * BulletinBoard represents the bulletin board server.
 */
class BulletinBoard() {
    private val signatureMap : HashMap<String, PublicKey> = HashMap()
    private lateinit var config : BulletinBoardConfigData

    val localhost = "http://localhost:3000/api"
    var numberOfVotes : Int = 0
    var votes : List<Vote> = mutableListOf()
    lateinit var votesSignature: ByteArray
    lateinit var rawVotes: BulletinBoardVotes

    val client : HttpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    /**
     * Load the votes from the bulletin board.
     */
    fun loadVotes() {
        rawVotes = sendGetRequest<BulletinBoardVotes>("$localhost/votes")
        votes = rawVotes.extractVotes()
        numberOfVotes = 2.0.pow(ceil(log2(votes.size.toDouble())).toInt()).toInt()
        votesSignature = CryptoUtils.hexStringToByteArray(rawVotes.signedHashedEncryptedVotes)
    }

    /**
     * Get the votes from the bulletin board.
     */
    @OptIn(ExperimentalStdlibApi::class)
    fun sendMixBatchOutput(index : Int, pollID: String, mixBatch : MixBatchOutput) {
        val header = toBase64(mixBatch.header)
        val cipherTextMatrix = toBase64(mixBatch.ciphertextsMatrix)
        val proofs = toBase64(mixBatch.proofsMatrix)
        val signature = mixBatch.getSignature().toHexString()
        val publicKey = edPublicKeyToBase64(mixBatch.ed25519PublicKey)

        val mixBatchOutputPayload = BulletinBoardMixBatchOutput(header, cipherTextMatrix, proofs)
        val payload = BulletinBoardMixBatchOutputData(index.toString(), mixBatchOutputPayload, signature, publicKey, pollID)

        runBlocking {
            client.post("$localhost/mix-batches") {
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
        }
    }

    /**
     * Load the bulletin board configuration.
     */
    fun loadBulletinBoardConfig() {
        config = sendGetRequest<BulletinBoardConfigData>("$localhost/bb-config")
    }

    /**
     * Get the bulletin board configuration.
     */
    fun getConfig() : BulletinBoardConfig {
        return config.bbConig
    }

    /**
     * Get the bulletin board configuration signature.
     */
    fun getConfigSignature() : ByteArray {
        return CryptoUtils.hexStringToByteArray(config.bbConfigSignature)
    }

    /**
     * Get the mix batch outputs for a given poll.
     */
    fun getMixBatchOutputs(pollID: String): Map<String, MixBatchOutput> {
        return sendGetRequest<BulletinBoardMixBatchOutputs>("$localhost/mix-batches/${pollID}").extract()
    }

    /**
     * Send the public key to the bulletin board.
     */
    fun sendVotingPublicKey(publicKey: ECPublicKey) {
        val payload = PublicKeyData(ecPublicKeyToHex(publicKey))

        runBlocking {
            client.post("$localhost/crypto/public-key") {
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
        }
    }

    /**
     * Send the votes to the bulletin board.
     */
    fun sendResults(verifierResults: List<VerifierResult>,
                    decryptionServersProofs: List<String>,
                    finalPollResults: Map<String, Int>) {
        val payload = Results(verifierResults, decryptionServersProofs, finalPollResults)

        runBlocking {
            client.post("$localhost/results") {
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
        }
    }


    fun startMix() : StartMix {
        return sendPutRequest<StartMix>("$localhost/polls/start-mix")
    }

    fun endMix() : EndMix {
        return sendPutRequest<EndMix>("$localhost/polls/end-mix")
    }

    /**
     * Send a PUT request to the given URL and return the response.
     */
    private inline fun <reified T> sendPutRequest(url : String) : T {
        return runBlocking {
            client.put(url).body()
        }
    }

    /**
     * Send a GET request to the given URL and return the response.
     */
    private inline fun <reified T> sendGetRequest(url : String) : T {
        return runBlocking {
            client.get(url).body()
        }
    }

    /**
     * convert a protobuf message to a base64 string
     */
    private fun toBase64(proto: AbstractMessage) : String {
        return Base64.getEncoder().encodeToString(proto.toByteArray())
    }

    /**
     * convert a list of protobuf messages to a list of base64 strings
     */
    private fun toBase64(matrix: List<List<AbstractMessage>>) : List<List<String>> {
        val result : MutableList<List<String>> = mutableListOf()

        for(column in matrix) {
            val list : MutableList<String> = mutableListOf()

            for(cell in column) {
                list.add(toBase64(cell))
            }

            result.add(list)
        }

        return result
    }
}

/**
 * Convert an Ed25519PublicKeyParameters to a base64 string.
 */
fun edPublicKeyToBase64(publicKey: Ed25519PublicKeyParameters): String {
    val keyBytes = ByteArray(Ed25519PublicKeyParameters.KEY_SIZE)
    publicKey.encode(keyBytes, 0)
    // Convert the byte array to a Base64-encoded string.
    return Base64.getEncoder().encodeToString(keyBytes)
}

/**
 * Convert an ECPublicKey to a hex string.
 */
fun ecPublicKeyToHex(publicKey: ECPublicKey, compressed: Boolean = false): String {
    val ecPoint = publicKey.w
    val x = ecPoint.affineX.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
    val y = ecPoint.affineY.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()

    // Ensure 32-byte padding for secp256k1/secp256r1
    val xPadded = ByteArray(32 - x.size) { 0 } + x
    val yPadded = ByteArray(32 - y.size) { 0 } + y

    return if (compressed) {
        // Compressed format: 0x02 if y is even, 0x03 if y is odd
        val prefix = if (yPadded.last().toInt() % 2 == 0) "02" else "03"
        prefix + xPadded.joinToString("") { "%02x".format(it) }
    } else {
        // Uncompressed format: 0x04 + X + Y
        "04" + xPadded.joinToString("") { "%02x".format(it) } + yPadded.joinToString("") { "%02x".format(it) }
    }
}