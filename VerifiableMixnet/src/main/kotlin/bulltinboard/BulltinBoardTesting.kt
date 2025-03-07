package org.example.bulltinboard

import bulltinboard.BulletinBoard
import meerkat.protobuf.Crypto
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import org.example.crypto.ThresholdCryptoConfig
import java.security.KeyFactory
import java.security.KeyPair
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

fun main() {
    // Add Bouncy Castle as a Security Provider
    Security.addProvider(BouncyCastleProvider())

    val bulletinBoard = BulletinBoard()
    val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters

//    val publicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFIPO1/uEgEP8F/lS6tThHf18uVUZjWwm5TM4k5h5Vb85GYZWinUr5dPuVEjuF6uBRau7tJOmzjizCiGHNjIR6A=="
//    val privateKeyBase64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgSKa1bzyOIoM45NGK0MePFi9VsC9puZMdBlvI0jm0BZygCgYIKoZIzj0DAQehRANCAAQUg87X+4SAQ/wX+VLq1OEd/Xy5VRmNbCblMziTmHlVvzkZhlaKdSvl0+5USO4Xq4FFq7u0k6bOOLMKIYc2MhHo"
//
//    val keyFactory = KeyFactory.getInstance("EC", "BC")
//
//    // Decode the Base64 encoded strings back into byte arrays
//    val ecPublicKeyBytes = Base64.getDecoder().decode(publicKeyBase64)
//    val ecPrivateKeyBytes = Base64.getDecoder().decode(privateKeyBase64)
//
//    // Decode the Base64 strings back into byte arrays
//    val publicKeySpec = X509EncodedKeySpec(ecPublicKeyBytes)
//    val privateKeySpec = PKCS8EncodedKeySpec(ecPrivateKeyBytes)
//
//    val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey
//    val privateKey = keyFactory.generatePrivate(privateKeySpec)

//    val pair : KeyPair = CryptoConfig.generateKeyPair()
//    val publicKey = pair.public as ECPublicKey
//    val privateKey = pair.private

//    val ecPoint = publicKey.w
//
//    // Convert X and Y coordinates to hexadecimal
//    val xHex = ecPoint.affineX.toByteArray().joinToString("") { "%02x".format(it) }
//    val yHex = ecPoint.affineY.toByteArray().joinToString("") { "%02x".format(it) }

//    println("Public Key X (Hex): $xHex")
//    println("Public Key Y (Hex): $yHex")

    val n = 6
    val t = 10

    val (publicKey, thresholdServers) = ThresholdCryptoConfig.generateThresholdKeyPair(n, t, SecureRandom.getInstanceStrong())

    bulletinBoard.sendPublicKey(publicKey)

//    ElGamal.encrypt(publicKey, "1", domainParameters)

    println("Waiting...")
    Thread.sleep(1 * 20 * 1000)

    println("JavaScript:")
    bulletinBoard.loadVotes()

    val decryptionServers = thresholdServers.shuffled().take(t)
    println(decryptionServers.size)

    for(vote in bulletinBoard.votes) {
        println("Vote: ${ThresholdCryptoConfig.thresholdDecrypt(vote.getEncryptedMessage(), decryptionServers).message}")
    }

    //    val serversManager = MixServersManager(publicKey, domainParameters, 0, bulletinBoard)

    //    val mixBatchOutputs = bulletinBoard.getMixBatchOutputs()

//    for(vote in bulletinBoard.votes) {
//        println("Vote: ${ElGamal.decrypt(privateKey, vote.getEncryptedMessage(), domainParameters)}")
//    }

//
//    serversManager.runServers()
//
//    Thread.sleep((1 * TIMEOUT + TIMEOUT).toLong())
//
//    val mixBatchOutputs = bulletinBoard.getMixBatchOutputs()
//
//    println(mixBatchOutputs)
}