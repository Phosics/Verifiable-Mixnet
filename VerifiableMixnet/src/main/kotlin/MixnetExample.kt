package org.example

import meerkat.protobuf.ConcreteCrypto
import mixnet.MixServersManager
import mixnet.Vote
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import org.example.crypto.CryptoUtils
import java.security.KeyPair
import java.security.PublicKey
import java.security.Security
import java.util.*


fun main() {
    // Register Bouncy Castle as a security provider
    Security.addProvider(BouncyCastleProvider())

    // Define the number of adversaries and votes
    val t = 1 // Number of adversaries
    val n = 8 // Number of votes (must be 2t +1 and a power of 2)

    // Initialize MixServersManager
    val mixServersManager = MixServersManager(t, n)

    // Generate EC-ElGamal key pair
    val keyPair: KeyPair = CryptoConfig.generateKeyPair()
    val publicKey: PublicKey = CryptoConfig.getPublicKey(keyPair)
    val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters

    // Define dummy messages for testing
    val dummyMessages = listOf(
        "VoteOne",
        "VoteTwo",
        "VoteThree",
        "VoteFour",
        "VoteFive",
        "VoteSix",
        "VoteSeven",
        "VoteEight"
    )

    // Encrypt the dummy messages to create Vote instances
    val votes: MutableList<Vote> = dummyMessages.mapIndexed { index, message ->
        // Encrypt the message using EC-ElGamal
        val encryptedMessage = ElGamal.encrypt(publicKey, message, domainParameters)

        // Create a Vote instance with the encrypted message
        Vote(encryptedMessage)
    }.toMutableList()

//    // Display Initial Votes
//    println("Initial Votes:")
//    votes.forEachIndexed { index, vote ->
//        println("Vote $index:")
//        println("Encrypted Message: ${vote.getEncryptedMessage().data.toHex()}")
//        println("--------------------------------------------------")
//    }

    // Apply the mixing operation
    val mixedVotes = mixServersManager.apply(votes)

//    // Display Final Mixed Votes
//    println("\nFinal Mixed Votes:")
//    mixedVotes.forEachIndexed { index, vote ->
//        println("Vote $index:")
//        println("Encrypted Message: ${vote.getEncryptedMessage().data.toHex()}")
//        println("--------------------------------------------------")
//    }

    // (Optional) Decrypt the mixed votes to verify correctness
    println("\nDecrypting Mixed Votes for Verification:")
    mixedVotes.forEachIndexed { index, vote ->
        val decryptedMessage = ElGamal.decrypt(
            CryptoConfig.getPrivateKey(keyPair),
            vote.getEncryptedMessage(),
            domainParameters
        )
        println("Decrypted Vote $index: $decryptedMessage")
    }
}

/**
 * Extension function to convert ByteString to hex string.
 */
fun ByteArray.toHex(): String {
    return org.bouncycastle.util.encoders.Hex.toHexString(this)
}
