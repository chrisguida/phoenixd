package fr.acinq.phoenixd.nwc

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

// -- Nostr Event (NIP-01) --

data class NostrEvent(
    val id: ByteVector32,
    val pubkey: ByteArray, // 32-byte x-only pubkey
    val createdAt: Long,
    val kind: Int,
    val tags: List<List<String>>,
    val content: String,
    val sig: ByteArray, // 64-byte Schnorr signature
) {
    fun toJson(): String {
        val tagsJson = tags.joinToString(",") { tag ->
            tag.joinToString(",") { "\"${jsonEscape(it)}\"" }.let { "[$it]" }
        }
        return """{"id":"${id.toHex()}","pubkey":"${pubkey.toHex()}","created_at":$createdAt,"kind":$kind,"tags":[$tagsJson],"content":"${jsonEscape(content)}","sig":"${sig.toHex()}"}"""
    }

    fun getTagValue(name: String): String? =
        tags.firstOrNull { it.size >= 2 && it[0] == name }?.get(1)

    fun getTagValues(name: String): List<String> =
        tags.filter { it.size >= 2 && it[0] == name }.map { it[1] }

    companion object {
        fun fromJson(json: JsonObject): NostrEvent {
            val id = ByteVector32.fromValidHex(json["id"]!!.jsonPrimitive.content)
            val pubkey = json["pubkey"]!!.jsonPrimitive.content.hexToByteArray()
            val createdAt = json["created_at"]!!.jsonPrimitive.long
            val kind = json["kind"]!!.jsonPrimitive.int
            val tags = json["tags"]!!.jsonArray.map { tagArray ->
                tagArray.jsonArray.map { it.jsonPrimitive.content }
            }
            val content = json["content"]!!.jsonPrimitive.content
            val sig = json["sig"]!!.jsonPrimitive.content.hexToByteArray()
            return NostrEvent(id, pubkey, createdAt, kind, tags, content, sig)
        }
    }
}

// -- Relay Messages (NIP-01) --

sealed class RelayMessage {
    data class Event(val subscriptionId: String, val event: NostrEvent) : RelayMessage()
    data class Ok(val eventId: String, val accepted: Boolean, val message: String) : RelayMessage()
    data class Eose(val subscriptionId: String) : RelayMessage()
    data class Notice(val message: String) : RelayMessage()
    data class Closed(val subscriptionId: String, val message: String) : RelayMessage()

    companion object {
        fun parse(text: String): RelayMessage? {
            val json = Json.parseToJsonElement(text).jsonArray
            return when (json[0].jsonPrimitive.content) {
                "EVENT" -> Event(
                    json[1].jsonPrimitive.content,
                    NostrEvent.fromJson(json[2].jsonObject)
                )
                "OK" -> Ok(
                    json[1].jsonPrimitive.content,
                    json[2].jsonPrimitive.boolean,
                    if (json.size > 3) json[3].jsonPrimitive.content else ""
                )
                "EOSE" -> Eose(json[1].jsonPrimitive.content)
                "NOTICE" -> Notice(json[1].jsonPrimitive.content)
                "CLOSED" -> Closed(
                    json[1].jsonPrimitive.content,
                    if (json.size > 2) json[2].jsonPrimitive.content else ""
                )
                else -> null
            }
        }
    }
}

// -- Client-to-Relay Messages --

object ClientMessage {
    fun event(event: NostrEvent): String = """["EVENT",${event.toJson()}]"""

    fun req(subscriptionId: String, filter: NostrFilter): String {
        val filterJson = filter.toJson()
        return """["REQ","$subscriptionId",$filterJson]"""
    }

    fun close(subscriptionId: String): String = """["CLOSE","$subscriptionId"]"""
}

data class NostrFilter(
    val kinds: List<Int>? = null,
    val authors: List<String>? = null,
    val tags: Map<String, List<String>>? = null,
    val since: Long? = null,
    val limit: Int? = null,
) {
    fun toJson(): String = buildJsonObject {
        kinds?.let { put("kinds", JsonArray(it.map { JsonPrimitive(it) })) }
        authors?.let { put("authors", JsonArray(it.map { JsonPrimitive(it) })) }
        tags?.forEach { (key, values) ->
            put("#$key", JsonArray(values.map { JsonPrimitive(it) }))
        }
        since?.let { put("since", it) }
        limit?.let { put("limit", it) }
    }.toString()
}

// -- NIP-47 Event Kinds --

object Nip47Kinds {
    const val INFO = 13194
    const val REQUEST = 23194
    const val RESPONSE = 23195
    const val NOTIFICATION = 23196
}

// -- NIP-47 Request/Response Types --

@Serializable
data class Nip47Request(
    val method: String,
    val params: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class Nip47Response(
    @SerialName("result_type") val resultType: String,
    val error: Nip47Error? = null,
    val result: JsonObject? = null,
)

@Serializable
data class Nip47Error(
    val code: String,
    val message: String,
) {
    companion object {
        const val RATE_LIMITED = "RATE_LIMITED"
        const val NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
        const val INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
        const val QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
        const val RESTRICTED = "RESTRICTED"
        const val UNAUTHORIZED = "UNAUTHORIZED"
        const val INTERNAL = "INTERNAL"
        const val OTHER = "OTHER"
        const val PAYMENT_FAILED = "PAYMENT_FAILED"
        const val NOT_FOUND = "NOT_FOUND"
    }
}

@Serializable
data class Nip47Notification(
    @SerialName("notification_type") val notificationType: String,
    val notification: JsonObject,
)

// NIP-47 method names
object Nip47Methods {
    const val PAY_INVOICE = "pay_invoice"
    const val MAKE_INVOICE = "make_invoice"
    const val GET_BALANCE = "get_balance"
    const val GET_INFO = "get_info"
    const val LOOKUP_INVOICE = "lookup_invoice"
    const val LIST_TRANSACTIONS = "list_transactions"

    val ALL = listOf(PAY_INVOICE, MAKE_INVOICE, GET_BALANCE, GET_INFO, LOOKUP_INVOICE, LIST_TRANSACTIONS)
}

// -- Helpers --

private fun jsonEscape(s: String): String = s
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n")
    .replace("\r", "\\r")
    .replace("\t", "\\t")

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

internal fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "hex string must have even length" }
    return ByteArray(length / 2) { i ->
        ((Character.digit(this[2 * i], 16) shl 4) + Character.digit(this[2 * i + 1], 16)).toByte()
    }
}
