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
import org.example.crypto.CryptoUtils
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.Vote
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.util.*
import kotlin.math.ceil
import kotlin.math.log2
import kotlin.math.pow

const val TIMEOUT = 5000

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

    fun loadVotes() {
        rawVotes = sendGetRequest<BulletinBoardVotes>("$localhost/votes")
        votes = rawVotes.extractVotes()
        numberOfVotes = 2.0.pow(ceil(log2(votes.size.toDouble())).toInt()).toInt()
        votesSignature = CryptoUtils.hexStringToByteArray(rawVotes.signedHashedEncryptedVotes)
    }

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

    fun loadBulletinBoardConfig() {
        config = sendGetRequest<BulletinBoardConfigData>("$localhost/bb-config")
    }

    fun getConfig() : BulletinBoardConfig {
        return config.bbConig
    }

    fun getConfigSignature() : ByteArray {
        return CryptoUtils.hexStringToByteArray(config.bbConfigSignature)
    }

    fun addSignaturePublicKey(index : String, publicKey: PublicKey) {
        signatureMap[index] = publicKey
    }

    fun getMixServerSignaturePublicKey(index : String) : PublicKey? {
        return signatureMap[index]
    }

    fun getMixBatchOutputs(pollID: String): Map<String, MixBatchOutput> {
        return sendGetRequest<BulletinBoardMixBatchOutputs>("$localhost/mix-batches/${pollID}").extract()
    }

    fun sendVotingPublicKey(publicKey: ECPublicKey) {
        val payload = PublicKeyData(ecPublicKeyToHex(publicKey))

        runBlocking {
            client.post("$localhost/crypto/public-key") {
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
        }
    }

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


    private inline fun <reified T> sendPutRequest(url : String) : T {
        return runBlocking {
            client.put(url).body()
        }
    }

    private inline fun <reified T> sendGetRequest(url : String) : T {
        return runBlocking {
            client.get(url).body()
        }
    }

    private fun convertPublicKey(publicKey: PublicKey): String {
        val encodedKey = publicKey.encoded
        val base64Encoded = Base64.getEncoder().encodeToString(encodedKey)
        val formattedBase64 = base64Encoded.chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$formattedBase64\n-----END PUBLIC KEY-----"
    }

    private fun toBase64(proto: AbstractMessage) : String {
        return Base64.getEncoder().encodeToString(proto.toByteArray())
    }

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

fun edPublicKeyToBase64(publicKey: Ed25519PublicKeyParameters): String {
    val keyBytes = ByteArray(Ed25519PublicKeyParameters.KEY_SIZE)
    publicKey.encode(keyBytes, 0)
    // Convert the byte array to a Base64-encoded string.
    return Base64.getEncoder().encodeToString(keyBytes)
}

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