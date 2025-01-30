package org.example

import meerkat.protobuf.Mixing
import mixnet.MixServersManager
import org.example.mixnet.Vote
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import org.example.mixnet.MixBatchOutput
import org.example.mixnet.Verifier
import java.security.KeyPair
import java.security.PublicKey
import java.security.Security

fun main() {
    // Register Bouncy Castle as a security provider
    Security.addProvider(BouncyCastleProvider())

    // Define the number of adversaries and votes
    val t = 1 // Number of adversaries
//    val n = 2 // Number of votes (must be 2t +1 and a power of 2)

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
        "VoteEight",
        "VoteOne",
        "VoteTwo",
        "VoteThree",
        "VoteFour",
        "VoteFive",
        "VoteSix",
        "VoteSeven",
        "VoteEight",
        "VoteOne",
        "VoteTwo",
        "VoteThree",
        "VoteFour",
        "VoteFive",
        "VoteSix",
        "VoteSeven",
        "VoteEight",
        "VoteOne",
        "VoteTwo",
        "VoteThree",
        "VoteFour",
        "VoteFive",
        "VoteSix",
        "VoteSeven",
        "VoteEight",


    )

    val n = dummyMessages.size

    // Initialize MixServersManager
    val mixServersManager = MixServersManager(publicKey, domainParameters, t, n)

    // Encrypt the dummy messages to create Vote instances
    val votes: MutableList<Vote> = dummyMessages.mapIndexed { index, message ->
        // Encrypt the message using EC-ElGamal
        val encryptedMessage = ElGamal.encrypt(publicKey, message, domainParameters)

        // Create a Vote instance with the encrypted message
        Vote(encryptedMessage)
    }.toMutableList()

    // Create MixBatchHeader
    val header = Mixing.MixBatchHeader.newBuilder()
        .setLogN(3) // log2(8) = 3
        .setLayers(3) // Typically equal to logN for a permutation network-based mix
        .build()

    // Apply the mixing operation and get MixBatchOutputs from each server
    val mixBatchOutputs: List<MixBatchOutput> = mixServersManager.processMixBatch(votes)

    // Print MixBatchOutput for each server
    mixBatchOutputs.forEachIndexed { index, mixBatchOutput ->
        println("MixBatchOutput for Server ${index + 1}:")
        println(mixBatchOutput)
        println("--------------------------------------------------")
    }

    // (Optional) Decrypt the mixed votes to verify correctness
    println("\nDecrypting Mixed Votes for Verification:")
    // Assuming mixBatchOutputs contain the final layer ciphertexts
    val finalLayerCiphertexts = mixBatchOutputs.last().ciphertextsMatrix.map { it.last() }
    finalLayerCiphertexts.forEachIndexed { index, ciphertext ->
        val decryptedMessage = ElGamal.decrypt(
            CryptoConfig.getPrivateKey(keyPair),
            ciphertext,
            domainParameters
        )
        println("Decrypted Vote $index: $decryptedMessage")
    }

    mixBatchOutputs.forEachIndexed { index, mixBatchOutput ->
        println("MixBatchOutput verifier for Server ${index + 1}:")
        println(Verifier(domainParameters, publicKey).verifyMixBatchOutput(mixBatchOutput))
        println("--------------------------------------------------")
    }
}
