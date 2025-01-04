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
     * Converts a string message to an ECPoint by embedding the message bytes and a counter into the x-coordinate.
     * This ensures a deterministic and reversible mapping.
     *
     * @param message The message string to convert.
     * @param domainParameters The EC domain parameters.
     * @return The corresponding ECPoint.
     * @throws IllegalArgumentException If a valid point cannot be found within the maximum attempts.
     */
    fun encodeMessageToECPoint(message: String, domainParameters: ECDomainParameters): ECPoint {
        val curve = domainParameters.curve
        val fieldSize = curve.fieldSize
        val byteLength = (fieldSize + 7) / 8
        val maxAttempts = 255 // Using 1 byte for the counter

        // Convert message to bytes
        val messageBytes = message.toByteArray(StandardCharsets.UTF_8)
        if (messageBytes.size > byteLength - 1) {
            throw IllegalArgumentException("Message too long to encode as ECPoint.")
        }

        for (counter in 0..maxAttempts) {
            // Prepend the counter byte to the message bytes
            val counterByte = counter.toByte()
            val paddedMessage = messageBytes + ByteArray(byteLength - 1 - messageBytes.size) { 0x00 }

            // Combine counter and padded message
            val combinedBytes = byteArrayOf(counterByte) + paddedMessage

            // Convert to BigInteger
            val x = BigInteger(1, combinedBytes)

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

            // If no valid point found, continue to next counter
        }

        throw IllegalArgumentException("Failed to map message to ECPoint within $maxAttempts attempts.")
    }

    /**
     * Converts an ECPoint back to a string message by extracting the x-coordinate and removing the counter and padding.
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

        // Extract the counter byte
        val counter = xBytes[0].toInt()

        // Extract the message bytes
        val messageBytes = xBytes.sliceArray(1 until byteLength)

        // Remove padding bytes (trailing zeros)
        val strippedMessageBytes = messageBytes.dropLastWhile { it == 0x00.toByte() }.toByteArray()

        return String(strippedMessageBytes, StandardCharsets.UTF_8)
    }
}