import org.bouncycastle.math.ec.ECPoint
import org.example.crypto.CryptoConfig
import org.example.crypto.MessageUtils

fun main() {
    val domainParameters =  CryptoConfig.ecDomainParameters
    var message : String
    var point : ECPoint

    for (i in 1..10) {
        message = i.toString()

        point = MessageUtils.encodeMessageToECPoint(message, domainParameters)

        println("Message $i")
        println("X: ${point.xCoord.toBigInteger()}")
        println("Y: ${point.yCoord.toBigInteger()}")
    }
}