package org.example.bulltinboard

import mixnet.MixServersManager
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.example.crypto.CryptoConfig
import org.example.crypto.ElGamal
import bulltinboard.BulletinBoard
import bulltinboard.TIMEOUT
import meerkat.protobuf.Mixing.MixBatchHeader
import java.security.KeyFactory
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

fun main() {
    // Add Bouncy Castle as a Security Provider
    Security.addProvider(BouncyCastleProvider())

    val publicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFIPO1/uEgEP8F/lS6tThHf18uVUZjWwm5TM4k5h5Vb85GYZWinUr5dPuVEjuF6uBRau7tJOmzjizCiGHNjIR6A=="
    val privateKeyBase64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgSKa1bzyOIoM45NGK0MePFi9VsC9puZMdBlvI0jm0BZygCgYIKoZIzj0DAQehRANCAAQUg87X+4SAQ/wX+VLq1OEd/Xy5VRmNbCblMziTmHlVvzkZhlaKdSvl0+5USO4Xq4FFq7u0k6bOOLMKIYc2MhHo"
    val domainParameters: ECDomainParameters = CryptoConfig.ecDomainParameters

    val bulletinBoard = BulletinBoard()

    val keyFactory = KeyFactory.getInstance("EC", "BC")

    // Decode the Base64 encoded strings back into byte arrays
    val ecPublicKeyBytes = Base64.getDecoder().decode(publicKeyBase64)
    val ecPrivateKeyBytes = Base64.getDecoder().decode(privateKeyBase64)

    // Decode the Base64 strings back into byte arrays
    val publicKeySpec = X509EncodedKeySpec(ecPublicKeyBytes)
    val privateKeySpec = PKCS8EncodedKeySpec(ecPrivateKeyBytes)

    val publicKey = keyFactory.generatePublic(publicKeySpec)
    val privateKey = keyFactory.generatePrivate(privateKeySpec)

    bulletinBoard.sendPublicKey(publicKey, CryptoConfig.EC_CURVE_NAME)

//    ElGamal.encrypt(publicKey, "1", domainParameters)

    val serversManager = MixServersManager(publicKey, domainParameters, 0, bulletinBoard)

    for(vote in bulletinBoard.votes) {
        println("Vote: ${ElGamal.decrypt(privateKey, vote.getEncryptedMessage(), domainParameters)}")
    }

    serversManager.runServers()

    Thread.sleep((1 * TIMEOUT + TIMEOUT).toLong())

    val mixBatchOutputs = bulletinBoard.getMixBatchOutputs()

    println(mixBatchOutputs.extract())
}