package org.example.bulltinboard

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import meerkat.protobuf.Crypto.RerandomizableEncryptedMessage
import org.example.mixnet.Vote
import java.security.PublicKey
import java.util.*

@Serializable
data class BulletinBoardVotes (
    var votes: List<BulletinBoardVote>
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
            val decodedVote = Base64.getDecoder().decode(vote.choice.data)
            mixnetVotes.add(Vote(RerandomizableEncryptedMessage.parseFrom(decodedVote)))
        }

        return mixnetVotes
    }
}

@Serializable
data class BulletinBoardVote (
    @SerialName("_id")
    val id: String,

    @SerialName("choice")
    val choice: BulletinBoardData,

    @SerialName("timestamp")
    val timestamp: String,

    @SerialName("signedChoice")
    val signature: BulletinBoardData
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