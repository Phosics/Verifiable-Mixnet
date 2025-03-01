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
import org.example.bulltinboard.BulletinBoardVotes
import org.example.bulltinboard.PublicKeyData
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.Vote
import java.security.PublicKey
import java.util.*
import kotlin.math.ceil
import kotlin.math.log2
import kotlin.math.pow

const val TIMEOUT = 5000

class BulletinBoard {
    val localhost = "http://localhost:3000/api"
    val votes : List<Vote>
    val numberOfVotes : Int

    val client : HttpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    init {
        votes = sendGetRequest<BulletinBoardVotes>("$localhost/votes").extractVotes()
        // TODO: verify
        // TODO: Browser should add dummy votes when finish voting
        numberOfVotes = 2.0.pow(ceil(log2(votes.size.toDouble())).toInt()).toInt()
    }

    fun sendMixBatchOutput(mixBatch : MixBatchOutput) {
        println(mixBatch)
        val header = toBase64(mixBatch.header)
        val cipherTextMatrix = toBase64(mixBatch.ciphertextsMatrix)
        val proofs = toBase64(mixBatch.proofsMatrix)

        val payload = BulletinBoardMixBatchOutput(header, cipherTextMatrix, proofs)

        runBlocking {
            client.post("$localhost/mixBatch") {
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
        }
    }

    fun getMixBatchOutputs(): List<MixBatchOutput> {
        return sendGetRequest<BulletinBoardMixBatchOutputs>("$localhost/mixBatch").extract()
    }

    fun sendPublicKey(publicKey: PublicKey) {
        val payload = PublicKeyData(convertPublicKey(publicKey))

        runBlocking {
            client.post("$localhost/crypto/public-key") {
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
        }
    }

    inline fun <reified T> sendGetRequest(url : String) : T {
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