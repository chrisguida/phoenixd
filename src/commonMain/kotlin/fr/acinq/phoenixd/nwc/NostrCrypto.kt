package fr.acinq.phoenixd.nwc

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.Digest
import fr.acinq.bitcoin.crypto.hmac
import fr.acinq.lightning.crypto.ChaCha20
import kotlin.random.Random

object NostrCrypto {

    // -- Event ID & Signing (NIP-01) --

    /** Compute the event ID: SHA256 of the serialized event commitment [0,pubkey,created_at,kind,tags,content]. */
    fun computeEventId(pubkey: ByteArray, createdAt: Long, kind: Int, tags: List<List<String>>, content: String): ByteVector32 {
        val tagsJson = tags.joinToString(",") { tag ->
            tag.joinToString(",") { "\"${jsonEscape(it)}\"" }.let { "[$it]" }
        }
        val serialized = """[0,"${pubkey.toHex()}",${createdAt},${kind},[$tagsJson],"${jsonEscape(content)}"]"""
        return ByteVector32(Crypto.sha256(serialized.encodeToByteArray()))
    }

    /** Sign a Nostr event with a private key (Schnorr/BIP-340). */
    fun signEvent(
        privateKey: PrivateKey,
        createdAt: Long,
        kind: Int,
        tags: List<List<String>>,
        content: String
    ): NostrEvent {
        val pubkeyXOnly = privateKey.publicKey().xOnly()
        val pubkeyBytes = pubkeyXOnly.value.toByteArray()
        val id = computeEventId(pubkeyBytes, createdAt, kind, tags, content)
        val sig = Crypto.signSchnorr(id, privateKey, null)
        return NostrEvent(
            id = id,
            pubkey = pubkeyBytes,
            createdAt = createdAt,
            kind = kind,
            tags = tags,
            content = content,
            sig = sig.toByteArray()
        )
    }

    // -- HKDF (RFC 5869) --

    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        return ikm.hmacSha256(salt)
    }

    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length <= 255 * 32) { "HKDF expand: output too long" }
        val n = (length + 31) / 32
        var t = ByteArray(0)
        val okm = ByteArray(length)
        var offset = 0
        for (i in 1..n) {
            val input = t + info + byteArrayOf(i.toByte())
            t = input.hmacSha256(prk)
            val copyLen = minOf(32, length - offset)
            t.copyInto(okm, offset, 0, copyLen)
            offset += copyLen
        }
        return okm
    }

    // -- NIP-44 v2 Encryption --

    /** Compute NIP-44 conversation key via ECDH + HKDF. */
    fun nip44ConversationKey(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        // ECDH: shared point = pubkey * privkey, then take x-coordinate (32 bytes)
        val sharedPoint = publicKey.times(privateKey)
        val sharedX = sharedPoint.xOnly().value.toByteArray()
        // HKDF extract with salt "nip44-v2"
        return hkdfExtract("nip44-v2".encodeToByteArray(), sharedX)
    }

    /** NIP-44 v2 encrypt. */
    fun nip44Encrypt(conversationKey: ByteArray, plaintext: String, nonce: ByteArray = Random.nextBytes(32)): String {
        require(nonce.size == 32) { "nonce must be 32 bytes" }
        val plaintextBytes = plaintext.encodeToByteArray()
        val padded = nip44Pad(plaintextBytes)

        val keys = nip44MessageKeys(conversationKey, nonce)

        // Encrypt with ChaCha20
        val ciphertext = ChaCha20.encrypt(padded, keys.chachaKey, keys.chachaNonce)

        // HMAC-SHA256(hmac_key, nonce || ciphertext) per NIP-44 spec
        val macInput = nonce + ciphertext
        val mac = macInput.hmacSha256(keys.hmacKey)

        // Final: base64(version(1) + nonce(32) + ciphertext(N) + mac(32))
        return (byteArrayOf(2) + nonce + ciphertext + mac).encodeBase64()
    }

    /** NIP-44 v2 decrypt. */
    fun nip44Decrypt(conversationKey: ByteArray, encoded: String): String {
        val data = encoded.decodeBase64()
        require(data.size >= 99) { "NIP-44 ciphertext too short" } // 1 + 32 + 32(min padded) + 2(len prefix) + 32(mac)
        require(data[0] == 2.toByte()) { "unsupported NIP-44 version: ${data[0]}" }

        val nonce = data.sliceArray(1..32)
        val ciphertext = data.sliceArray(33 until data.size - 32)
        val mac = data.sliceArray(data.size - 32 until data.size)

        // Derive keys
        val keys = nip44MessageKeys(conversationKey, nonce)

        // Verify HMAC: HMAC-SHA256(hmac_key, nonce || ciphertext)
        val macInput = nonce + ciphertext
        val expectedMac = macInput.hmacSha256(keys.hmacKey)
        require(expectedMac.contentEquals(mac)) { "NIP-44 HMAC verification failed" }

        // Decrypt
        val padded = ChaCha20.decrypt(ciphertext, keys.chachaKey, keys.chachaNonce)

        return nip44Unpad(padded)
    }

    // -- NIP-44 Padding --

    private fun nip44Pad(plaintext: ByteArray): ByteArray {
        val len = plaintext.size
        require(len in 1..65535) { "plaintext too long for NIP-44" }
        val paddedLen = calcPaddedLen(len)
        val result = ByteArray(2 + paddedLen)
        // Big-endian 2-byte length prefix
        result[0] = (len shr 8).toByte()
        result[1] = (len and 0xFF).toByte()
        plaintext.copyInto(result, 2)
        return result
    }

    private fun nip44Unpad(padded: ByteArray): String {
        require(padded.size >= 2) { "padded data too short" }
        val len = ((padded[0].toInt() and 0xFF) shl 8) or (padded[1].toInt() and 0xFF)
        require(len > 0 && 2 + len <= padded.size) { "invalid NIP-44 padding" }
        // Verify padding is zero-filled
        for (i in 2 + len until padded.size) {
            require(padded[i] == 0.toByte()) { "non-zero padding byte" }
        }
        return padded.sliceArray(2 until 2 + len).decodeToString()
    }

    internal fun calcPaddedLen(unpaddedLen: Int): Int {
        if (unpaddedLen <= 32) return 32
        val nextPow2 = Integer.highestOneBit(unpaddedLen - 1) shl 1
        val chunk = maxOf(32, nextPow2 / 8)
        return ((unpaddedLen + chunk - 1) / chunk) * chunk
    }

    // -- NIP-44 Message Key Derivation --

    data class Nip44MessageKeys(
        val chachaKey: ByteArray,
        val chachaNonce: ByteArray,
        val hmacKey: ByteArray,
    )

    private fun nip44MessageKeys(conversationKey: ByteArray, nonce: ByteArray): Nip44MessageKeys {
        val expanded = hkdfExpand(conversationKey, nonce, 76)
        return Nip44MessageKeys(
            chachaKey = expanded.sliceArray(0 until 32),
            chachaNonce = expanded.sliceArray(32 until 44),
            hmacKey = expanded.sliceArray(44 until 76),
        )
    }

    // -- Helpers --

    private fun ByteArray.hmacSha256(key: ByteArray): ByteArray {
        return Digest.sha256().hmac(key, this, 64)
    }

    private fun jsonEscape(s: String): String = s
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

// Base64 encode/decode helpers (no-padding)
internal fun ByteArray.encodeBase64(): String {
    val table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    val sb = StringBuilder()
    var i = 0
    while (i < size) {
        val b0 = this[i].toInt() and 0xFF
        if (i + 2 < size) {
            val b1 = this[i + 1].toInt() and 0xFF
            val b2 = this[i + 2].toInt() and 0xFF
            sb.append(table[(b0 shr 2) and 0x3F])
            sb.append(table[((b0 shl 4) or (b1 shr 4)) and 0x3F])
            sb.append(table[((b1 shl 2) or (b2 shr 6)) and 0x3F])
            sb.append(table[b2 and 0x3F])
        } else if (i + 1 < size) {
            val b1 = this[i + 1].toInt() and 0xFF
            sb.append(table[(b0 shr 2) and 0x3F])
            sb.append(table[((b0 shl 4) or (b1 shr 4)) and 0x3F])
            sb.append(table[(b1 shl 2) and 0x3F])
            sb.append('=')
        } else {
            sb.append(table[(b0 shr 2) and 0x3F])
            sb.append(table[(b0 shl 4) and 0x3F])
            sb.append("==")
        }
        i += 3
    }
    return sb.toString()
}

internal fun String.decodeBase64(): ByteArray {
    val table = IntArray(256) { -1 }
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".forEachIndexed { i, c -> table[c.code] = i }
    val input = trimEnd('=')
    val output = ByteArray(input.length * 3 / 4)
    var outIdx = 0
    var i = 0
    while (i < input.length) {
        val a = table[input[i].code]
        val b = if (i + 1 < input.length) table[input[i + 1].code] else 0
        val c = if (i + 2 < input.length) table[input[i + 2].code] else 0
        val d = if (i + 3 < input.length) table[input[i + 3].code] else 0
        output[outIdx++] = ((a shl 2) or (b shr 4)).toByte()
        if (i + 2 < input.length) output[outIdx++] = (((b and 0xF) shl 4) or (c shr 2)).toByte()
        if (i + 3 < input.length) output[outIdx++] = (((c and 0x3) shl 6) or d).toByte()
        i += 4
    }
    return output.copyOf(outIdx)
}
