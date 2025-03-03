//package org.example
//
//import org.example.mixnet.Vote
//import org.bouncycastle.crypto.params.ECDomainParameters
//import org.bouncycastle.jce.provider.BouncyCastleProvider
//import org.example.crypto.CryptoConfig
//import org.example.crypto.ElGamal
//import java.security.KeyPair
//import java.security.PublicKey
//import java.security.Security
//
//fun main() {
//    // Register Bouncy Castle as a security provider
//    Security.addProvider(BouncyCastleProvider())
//
//    // Define the number of adversaries and votes
//    val t = 1 // Number of adversaries
//    val n = 8 // Number of votes (must be 2t +1 and a power of 2)
//
//    // Generate EC-ElGamal key pair
//    val keyPair: KeyPair = CryptoConfig.generateKeyPair()
//    val publicKey: PublicKey = CryptoConfig.getPublicKey(keyPair)
//    val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters
//
//    // Encrypt the dummy messages to create Vote instances
//    val votes: MutableList<Vote> = dummyMessages.mapIndexed { index, message ->
//        // Encrypt the message using EC-ElGamal
//        val encryptedMessage = ElGamal.encrypt(publicKey, message, domainParameters)
//
//        // Create a Vote instance with the encrypted message
//        Vote(encryptedMessage)
//    }.toMutableList()
//
//    votingManager.startVotingSession()
//
//    for (vote in votes) {
//        votingManager.vote(vote)
//    }
//
//    votingManager.endVotingSession()
//
////    // Print MixBatchOutput for each server
////    mixBatchOutputs.forEachIndexed { index, mixBatchOutput ->
////        println("MixBatchOutput for Server ${index + 1}:")
////        println(mixBatchOutput)
////        println("--------------------------------------------------")
////    }
////
////    // (Optional) Decrypt the mixed votes to verify correctness
////    println("\nDecrypting Mixed Votes for Verification:")
////    // Assuming mixBatchOutputs contain the final layer ciphertexts
////    val finalLayerCiphertexts = mixBatchOutputs.last().ciphertextsMatrix.map { it.last() }
////    finalLayerCiphertexts.forEachIndexed { index, ciphertext ->
////        val decryptedMessage = ElGamal.decrypt(
////            CryptoConfig.getPrivateKey(keyPair),
////            ciphertext,
////            domainParameters
////        )
////        println("Decrypted Vote $index: $decryptedMessage")
////    }
////
////    mixBatchOutputs.forEachIndexed { index, mixBatchOutput ->
////        println("MixBatchOutput verifier for Server ${index + 1}:")
////        println(mixBatchOutput.verifyMixBatch())
////        println("--------------------------------------------------")
////    }
//}
