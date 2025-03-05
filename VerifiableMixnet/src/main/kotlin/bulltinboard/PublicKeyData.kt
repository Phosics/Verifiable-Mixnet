package org.example.bulltinboard

import kotlinx.serialization.Serializable

@Serializable
data class PublicKeyData(
    val publicKeyHex: String) {
}