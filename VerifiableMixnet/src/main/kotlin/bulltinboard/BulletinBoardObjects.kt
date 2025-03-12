package bulltinboard

import com.google.gson.Gson
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import meerkat.protobuf.Mixing.Mix2Proof
import meerkat.protobuf.Mixing.MixBatchHeader
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.util.io.pem.PemReader
import org.example.crypto.CryptoUtils
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.Vote
import java.io.StringReader
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.Base64.Decoder
import kotlin.collections.HashMap

@Serializable
data class StartMix(
    @SerialName("started")
    val started : Boolean,
    @SerialName("message")
    val message : String,
    @SerialName("pollId")
    val pollId : String
)

@Serializable
data class EndMix(
    @SerialName("ended")
    val ended : Boolean,
    @SerialName("message")
    val message : String,
    @SerialName("pollId")
    val pollId : String,
    @SerialName("startedDecoding")
    val startedDecoding: Boolean
)

@Serializable
data class BulletinBoardVotes (
    @SerialName("votes")
    val votes: List<BulletinBoardVote>,
    @SerialName("signedHashedEncryptedVotes")
    val signedHashedEncryptedVotes: String
) {
    fun verifyVotes(publicKey: PublicKey) : List<BulletinBoardVote> {
        val failed : MutableList<BulletinBoardVote> = mutableListOf()

        for (vote in votes) {
            if(!vote.verifySignature(publicKey)) {
                failed.add(vote)
            }
        }

        return failed
    }

    fun extractVotes() : List<Vote> {
        val mixnetVotes : MutableList<Vote> = mutableListOf()

        for (vote in votes) {
            val bytes = CryptoUtils.hexStringToByteArray(vote.choice)
            mixnetVotes.add(Vote(RerandomizableEncryptedMessage.parseFrom(bytes)))
        }

        return mixnetVotes
    }
}

@Serializable
data class BulletinBoardVote (
    @SerialName("_id")
    val id: String,
    @SerialName("choice")
    val choice: String,
    @SerialName("timestamp")
    val timestamp: String,
    @SerialName("pollId")
    val pollId: String,
    @SerialName("userId")
    val userId: String,
    @SerialName("signedEncryptedVote")
    val signedEncryptedVote: String
) {
    fun verifySignature(publicKey : PublicKey) : Boolean {
        // TODO: Fill
        return true
    }
}

@Serializable
data class BulletinBoardData (
    val data : String
)

@Serializable
data class BulletinBoardMixBatchOutput(
    val header : String,
    val ciphertextsMatrix : List<List<String>>,
    val proofsMatrix : List<List<String>>) {

    fun decodeProofsMatrix(decoder: Decoder) : List<List<Mix2Proof>> {
        val result : MutableList<List<Mix2Proof>> = mutableListOf()

        for (row in proofsMatrix) {
            val colResult : MutableList<Mix2Proof> = mutableListOf()

            for (cell in row) {
                colResult.add(Mix2Proof.parseFrom(decoder.decode(cell)))
            }

            result.add(colResult)
        }

        return result
    }

    fun decodeCiphertextsMatrix(decoder: Decoder) : List<List<RerandomizableEncryptedMessage>> {
        val result : MutableList<List<RerandomizableEncryptedMessage>> = mutableListOf()

        for (row in ciphertextsMatrix) {
            val colResult : MutableList<RerandomizableEncryptedMessage> = mutableListOf()

            for (cell in row) {
                colResult.add(RerandomizableEncryptedMessage.parseFrom(decoder.decode(cell)))
            }

            result.add(colResult)
        }

        return result
    }

    fun decodeHeader(decoder : Decoder): MixBatchHeader {
        return MixBatchHeader.parseFrom(decoder.decode(header))
    }
}

@Serializable
data class BulletinBoardMixBatchOutputData(
    val index : String,
    val mixBatch: BulletinBoardMixBatchOutput,
    val signature: String,
    val publicKey: String,
    val pollId: String) {
}

@Serializable
data class BulletinBoardMixBatchOutputRecord(
    @SerialName("_id")
    val id : String,
    @SerialName("index")
    val index : String,
    @SerialName("mixBatch")
    val mixBatchOutput: BulletinBoardMixBatchOutput,
    @SerialName("timestamp")
    val timestamp: String,
    @SerialName("signature")
    val signature: String,
    @SerialName("publicKey")
    val publicKey: String,
    @SerialName("pollId")
    val pollId: String
) {
    fun extract(): MixBatchOutput {
        val decoder = Base64.getDecoder()
        val header = mixBatchOutput.decodeHeader(decoder)
        val ciphertextsMatrix = mixBatchOutput.decodeCiphertextsMatrix(decoder)
        val proofsMatrix = mixBatchOutput.decodeProofsMatrix(decoder)
        val signature = signature.toByteArray()
        val publicKey = base64ToEd25519PublicKey(publicKey)

        val mixBatch = MixBatchOutput(header, ciphertextsMatrix, proofsMatrix, publicKey)
        mixBatch.setSignature(signature)

        return mixBatch
    }

    private fun base64ToEd25519PublicKey(publicKeyBase64: String): Ed25519PublicKeyParameters {
        // Decode the Base64 string to a byte array.
        val keyBytes = Base64.getDecoder().decode(publicKeyBase64)

        // Optionally, check if the decoded key has the expected length.
        if (keyBytes.size != Ed25519PublicKeyParameters.KEY_SIZE) {
            throw IllegalArgumentException("Invalid key length: ${keyBytes.size}")
        }

        // Create an Ed25519PublicKeyParameters instance using the byte array.
        return Ed25519PublicKeyParameters(keyBytes, 0)
    }
}

@Serializable
data class BulletinBoardMixBatchOutputs(
    val mixBatches : List<BulletinBoardMixBatchOutputRecord>
) {
    fun extract() : Map<String, MixBatchOutput> {
        val result : HashMap<String, MixBatchOutput> = HashMap()

        for (mixBatch in mixBatches) {
            result[mixBatch.index] = mixBatch.extract()
        }

        return result
    }
}

@Serializable
data class Results(
    val verifierResults: String,
    val decryptionServersProofs: String,
    val finalPollResults: String
)

@Serializable
data class PublicKeyData(
    val publicKeyHex: String)

@Serializable
data class BulletinBoardConfig(
    @SerialName("_id")
    val id: String,
    @SerialName("mixServersMalicious")
    val mixServersMalicious: Int,
    @SerialName("decryptionServersRequired")
    val decryptionServersRequired: Int,
    @SerialName("decryptionServerTotal")
    val decryptionServerTotal: Int,
    @SerialName("publicKey")
    val publicKey: String,
    @SerialName("timestamp")
    val timestamp: String
) {
    fun getPublicKey(): Ed25519PublicKeyParameters {
        // Create a PemReader to parse the PEM string
        val pemReader = PemReader(StringReader(publicKey))
        val pemObject = pemReader.readPemObject()
        pemReader.close()

        // The content should be an X.509 SubjectPublicKeyInfo structure
        val spki = SubjectPublicKeyInfo.getInstance(pemObject.content)

        // Extract the raw public key bytes from the structure
        val keyBytes = spki.publicKeyData.bytes

        // Create and return the Ed25519PublicKeyParameters (offset is 0)
        return Ed25519PublicKeyParameters(keyBytes, 0)
    }

    override fun toString(): String {
        return Json.encodeToString(this)
    }
}


@Serializable
data class BulletinBoardConfigData(
    @SerialName("bbConfig")
    val bbConig: BulletinBoardConfig,
    @SerialName("bbConfigSignature")
    val bbConfigSignature: String
)

