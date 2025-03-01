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
            val bytes = hexStringToByteArray(vote.choice)
            mixnetVotes.add(Vote(RerandomizableEncryptedMessage.parseFrom(bytes)))
        }

        return mixnetVotes
    }

    /**
     * Converts a hex string to a ByteArray.
     *
     * @param hex The hex string to convert.
     * @return The resulting ByteArray.
     * @throws IllegalArgumentException If the hex string is invalid.
     */
    private fun hexStringToByteArray(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Invalid hex string: length must be even." }
        return ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
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

    @SerialName("signedChoice")
    val signature: String
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