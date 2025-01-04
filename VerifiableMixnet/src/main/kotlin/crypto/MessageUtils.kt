package org.example.crypto

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.nio.charset.StandardCharsets

/**
 * MessageUtils provides utility functions for message encoding and decoding.
 */
object MessageUtils {

    /**
     * Converts a string message to an ECPoint by embedding the message bytes into the x-coordinate.
     * Uses fixed-length encoding with padding to ensure reversibility.
     *
     * @param message The message string to convert.
     * @param domainParameters The EC domain parameters.
     * @return The corresponding ECPoint.
     * @throws IllegalArgumentException If a valid point cannot be found.
     */
    fun encodeMessageToECPoint(message: String, domainParameters: ECDomainParameters): ECPoint {
        val messageBytes = message.toByteArray(StandardCharsets.UTF_8)
        val curve = domainParameters.curve
        val fieldSize = curve.fieldSize
        val byteLength = (fieldSize + 7) / 8

        // Define maximum message length based on field size
        if (messageBytes.size > byteLength) {
            throw IllegalArgumentException("Message too long to encode as ECPoint.")
        }

        // Pad the message with trailing zeros to reach fixed length
        val paddedMessage = messageBytes + ByteArray(byteLength - messageBytes.size) { 0x00 }

        // Convert padded message to BigInteger
        val x = BigInteger(1, paddedMessage)

        // Prepare x-coordinate bytes
        var xBytes = x.toByteArray()
        xBytes = when {
            xBytes.size < byteLength -> ByteArray(byteLength - xBytes.size) { 0x00.toByte() } + xBytes
            xBytes.size > byteLength -> xBytes.takeLast(byteLength).toByteArray()
            else -> xBytes
        }

        // Attempt to decode ECPoint with both y-coordinate parities
        val prefixes = listOf(0x02.toByte(), 0x03.toByte()) // 0x02 for even y, 0x03 for odd y

        for (prefix in prefixes) {
            try {
                val encodedPoint = byteArrayOf(prefix) + xBytes
                val point = curve.decodePoint(encodedPoint)
                if (point.isValid) {
                    return point
                }
            } catch (e: Exception) {
                // Invalid point, try next prefix
            }
        }

        // If no valid point is found, throw exception
        throw IllegalArgumentException("Failed to map message to ECPoint.")
    }

    /**
     * Converts an ECPoint back to a string message by extracting the x-coordinate.
     * Removes any padding bytes that were added during encoding.
     *
     * @param point The ECPoint to convert.
     * @return The corresponding string message.
     */
    fun decodeECPointToMessage(point: ECPoint): String {
        val xBigInt = point.xCoord.toBigInteger()
        var xBytes = xBigInt.toByteArray()

        // Determine byte length based on the curve's field size
        val curve = point.curve
        val fieldSize = curve.fieldSize
        val byteLength = (fieldSize + 7) / 8

        // Adjust byte array to match the expected length
        xBytes = when {
            xBytes.size < byteLength -> ByteArray(byteLength - xBytes.size) { 0x00.toByte() } + xBytes
            xBytes.size > byteLength -> xBytes.takeLast(byteLength).toByteArray()
            else -> xBytes
        }

        // Remove trailing zeros (padding)
        xBytes = xBytes.dropLastWhile { it == 0x00.toByte() }.toByteArray()

        return String(xBytes, StandardCharsets.UTF_8)
    }
}