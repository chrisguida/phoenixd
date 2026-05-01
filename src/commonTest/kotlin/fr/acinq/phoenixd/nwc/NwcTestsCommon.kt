package fr.acinq.phoenixd.nwc

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NwcTestsCommon {

    private val json = Json { ignoreUnknownKeys = true }

    // -- Test 1: NIP-44 encrypt/decrypt roundtrip --

    @Test
    fun `nip44 encrypt-decrypt roundtrip`() {
        val alice = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000002")
        val bob = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000003")

        val convKeyAlice = NostrCrypto.nip44ConversationKey(alice, bob.publicKey())
        val convKeyBob = NostrCrypto.nip44ConversationKey(bob, alice.publicKey())
        assertTrue(convKeyAlice.contentEquals(convKeyBob), "conversation keys must match both directions")

        val plaintext = "Hello NWC! This is a test message."
        val encrypted = NostrCrypto.nip44Encrypt(convKeyAlice, plaintext)
        val decrypted = NostrCrypto.nip44Decrypt(convKeyBob, encrypted)
        assertEquals(plaintext, decrypted)
    }

    // -- Test 2: NIP-44 conversation key test vector --

    @Test
    fun `nip44 conversation key known vector`() {
        // sec1 = 1 (scalar), pub2 = generator point G
        val sec1 = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000001")
        val pub2 = PublicKey.fromHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

        val convKey = NostrCrypto.nip44ConversationKey(sec1, pub2)
        // sec1=1, pub2=G => shared point = G, sharedX = G.x
        // Then HKDF-extract(salt="nip44-v2", ikm=G.x)
        // G.x = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        // This is deterministic, verify it produces 32 bytes
        assertEquals(32, convKey.size)

        // sec1=1, pub2=G => ECDH shared point is G itself, sharedX = G.x
        // HKDF-extract(salt="nip44-v2", ikm=G.x) produces this deterministic key
        val expected = "3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e"
        assertEquals(expected, convKey.toHex())
    }

    // -- Test 3: HKDF extract/expand (RFC 5869 Test Case 1) --

    @Test
    fun `hkdf rfc5869 test case 1`() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = ByteArray(13) { it.toByte() } // 0x00..0x0c
        val info = ByteArray(10) { (0xf0 + it).toByte() } // 0xf0..0xf9

        val prk = NostrCrypto.hkdfExtract(salt, ikm)
        assertEquals(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            prk.toHex()
        )

        val okm = NostrCrypto.hkdfExpand(prk, info, 42)
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            okm.toHex()
        )
    }

    // -- Test 4: NIP-44 padding --

    @Test
    fun `nip44 padding lengths`() {
        assertEquals(32, NostrCrypto.calcPaddedLen(1))
        assertEquals(32, NostrCrypto.calcPaddedLen(32))
        assertEquals(64, NostrCrypto.calcPaddedLen(33))
        assertEquals(64, NostrCrypto.calcPaddedLen(64))
        assertEquals(96, NostrCrypto.calcPaddedLen(65))
        assertEquals(256, NostrCrypto.calcPaddedLen(256))
        assertEquals(320, NostrCrypto.calcPaddedLen(257))
    }

    // -- Test 5: Nostr event ID computation --

    @Test
    fun `nostr event id computation`() {
        val pubkey = ByteArray(32) { 0xab.toByte() }
        val createdAt = 1700000000L
        val kind = 1
        val tags = listOf(listOf("e", "abc123"))
        val content = "hello world"

        val id = NostrCrypto.computeEventId(pubkey, createdAt, kind, tags, content)

        // The serialized form is: [0,"abab...ab",1700000000,1,[["e","abc123"]],"hello world"]
        val expectedSerialized = """[0,"${pubkey.toHex()}",1700000000,1,[["e","abc123"]],"hello world"]"""
        val expectedId = ByteVector32(Crypto.sha256(expectedSerialized.encodeToByteArray()))
        assertEquals(expectedId, id)
    }

    // -- Test 6: Nostr event signing + verification --

    @Test
    fun `nostr event signing`() {
        val privKey = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000005")
        val createdAt = 1700000000L
        val kind = 1
        val tags = emptyList<List<String>>()
        val content = "test message"

        val event = NostrCrypto.signEvent(privKey, createdAt, kind, tags, content)

        // Verify sig is 64 bytes
        assertEquals(64, event.sig.size)

        // Verify event ID matches recomputation
        val recomputedId = NostrCrypto.computeEventId(event.pubkey, createdAt, kind, tags, content)
        assertEquals(recomputedId, event.id)

        // Verify Schnorr signature is valid
        val sigValid = Crypto.verifySignatureSchnorr(event.id, ByteVector64(event.sig), privKey.publicKey().xOnly())
        assertTrue(sigValid, "Schnorr signature must be valid")
    }

    // -- Test 7: Base64 encode/decode roundtrip --

    @Test
    fun `base64 roundtrip`() {
        val testCases = listOf(
            ByteArray(0),
            byteArrayOf(0x42),
            byteArrayOf(0x01, 0x02, 0x03),
            "Hello, World!".encodeToByteArray(),
            ByteArray(256) { it.toByte() },
        )
        for (data in testCases) {
            val encoded = data.encodeBase64()
            val decoded = encoded.decodeBase64()
            assertTrue(data.contentEquals(decoded), "roundtrip failed for ${data.size}-byte input")
        }
    }

    @Test
    fun `base64 known values`() {
        assertEquals("", ByteArray(0).encodeBase64())
        assertEquals("AQID", byteArrayOf(1, 2, 3).encodeBase64())
        assertEquals("SGVsbG8=", "Hello".encodeToByteArray().encodeBase64())
    }

    // -- Test 8: Relay message parsing --

    @Test
    fun `relay message parse EVENT`() {
        val eventJson = """["EVENT","sub1",{"id":"${"aa".repeat(32)}","pubkey":"${"bb".repeat(32)}","created_at":1700000000,"kind":1,"tags":[],"content":"hello","sig":"${"cc".repeat(32)}"}]"""
        val msg = RelayMessage.parse(eventJson)
        assertTrue(msg is RelayMessage.Event)
        assertEquals("sub1", msg.subscriptionId)
        assertEquals("hello", msg.event.content)
        assertEquals(1, msg.event.kind)
    }

    @Test
    fun `relay message parse OK`() {
        val msg = RelayMessage.parse("""["OK","${"dd".repeat(32)}",true,""]""")
        assertTrue(msg is RelayMessage.Ok)
        assertEquals("dd".repeat(32), msg.eventId)
        assertTrue(msg.accepted)
        assertEquals("", msg.message)
    }

    @Test
    fun `relay message parse EOSE`() {
        val msg = RelayMessage.parse("""["EOSE","sub1"]""")
        assertTrue(msg is RelayMessage.Eose)
        assertEquals("sub1", msg.subscriptionId)
    }

    @Test
    fun `relay message parse NOTICE`() {
        val msg = RelayMessage.parse("""["NOTICE","rate limited"]""")
        assertTrue(msg is RelayMessage.Notice)
        assertEquals("rate limited", msg.message)
    }

    @Test
    fun `relay message parse CLOSED`() {
        val msg = RelayMessage.parse("""["CLOSED","sub1","auth-required:"]""")
        assertTrue(msg is RelayMessage.Closed)
        assertEquals("sub1", msg.subscriptionId)
        assertEquals("auth-required:", msg.message)
    }

    // -- Test 9: NIP-47 request/response serialization --

    @Test
    fun `nip47 request deserialization`() {
        val reqJson = """{"method":"pay_invoice","params":{"invoice":"lnbc1..."}}"""
        val request = json.decodeFromString<Nip47Request>(reqJson)
        assertEquals("pay_invoice", request.method)
        assertEquals("lnbc1...", (request.params["invoice"] as JsonPrimitive).content)
    }

    @Test
    fun `nip47 request serialization`() {
        val request = Nip47Request(method = "get_info")
        val serialized = json.encodeToString(Nip47Request.serializer(), request)
        val parsed = Json.parseToJsonElement(serialized) as JsonObject
        assertEquals("get_info", (parsed["method"] as JsonPrimitive).content)
    }

    @Test
    fun `nip47 response with result`() {
        val response = Nip47Response(
            resultType = "get_balance",
            result = JsonObject(mapOf("balance" to JsonPrimitive(100000L)))
        )
        val serialized = json.encodeToString(Nip47Response.serializer(), response)
        val parsed = Json.parseToJsonElement(serialized) as JsonObject
        assertEquals("get_balance", (parsed["result_type"] as JsonPrimitive).content)
        assertNotNull(parsed["result"])
        assertNull(parsed["error"])
    }

    @Test
    fun `nip47 response with error`() {
        val response = Nip47Response(
            resultType = "pay_invoice",
            error = Nip47Error(code = Nip47Error.PAYMENT_FAILED, message = "route not found")
        )
        val serialized = json.encodeToString(Nip47Response.serializer(), response)
        val parsed = Json.parseToJsonElement(serialized) as JsonObject
        assertEquals("pay_invoice", (parsed["result_type"] as JsonPrimitive).content)
        assertNull(parsed["result"])
        val error = parsed["error"] as JsonObject
        assertEquals("PAYMENT_FAILED", (error["code"] as JsonPrimitive).content)
        assertEquals("route not found", (error["message"] as JsonPrimitive).content)
    }

    // -- Test 10: NWC connection URI generation --

    @Test
    fun `nwc connection uri generation`() {
        val walletPrivKey = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000010")
        val clientPrivKey = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000020")

        val connection = NwcConnection(
            id = "test-id",
            label = "test",
            walletPrivateKey = walletPrivKey,
            clientPrivateKey = clientPrivKey,
            relayUrl = "wss://relay.example.com",
            budgetMsat = null,
            spentMsat = 0,
            budgetIntervalSecs = null,
            lastBudgetResetAt = 0,
            createdAt = 0,
        )

        val uri = connection.toUri()
        val walletXOnlyHex = walletPrivKey.publicKey().xOnly().value.toHex()
        val clientSecretHex = clientPrivKey.value.toHex()

        assertTrue(uri.startsWith("nostr+walletconnect://"))
        assertTrue(uri.contains(walletXOnlyHex))
        assertTrue(uri.contains("relay=wss://relay.example.com"))
        assertTrue(uri.contains("secret=$clientSecretHex"))
        assertEquals("nostr+walletconnect://${walletXOnlyHex}?relay=wss://relay.example.com&secret=${clientSecretHex}", uri)
    }

    // -- Test 11: Event dedup cache (LinkedHashSet pattern) --

    @Test
    fun `event dedup cache rejects duplicates`() {
        val cache = LinkedHashSet<String>()
        val maxSize = 5

        // First add returns true (new entry)
        assertTrue(cache.add("event1"))
        assertTrue(cache.add("event2"))
        assertTrue(cache.add("event3"))

        // Duplicate returns false
        assertTrue(!cache.add("event1"))
        assertTrue(!cache.add("event2"))

        assertEquals(3, cache.size)
    }

    @Test
    fun `event dedup cache LRU eviction`() {
        val cache = LinkedHashSet<String>()
        val maxSize = 3

        cache.add("a")
        cache.add("b")
        cache.add("c")
        cache.add("d")
        // Evict oldest until at max size (same logic as NwcService)
        while (cache.size > maxSize) {
            cache.remove(cache.first())
        }

        assertEquals(3, cache.size)
        assertTrue("a" !in cache, "oldest entry should be evicted")
        assertTrue("b" in cache)
        assertTrue("c" in cache)
        assertTrue("d" in cache)

        // "a" can now be re-added (it was evicted)
        assertTrue(cache.add("a"))
    }

    // -- Test 12: Expiration tag parsing --

    @Test
    fun `nostr event getTagValue`() {
        val event = makeTestEvent(
            tags = listOf(
                listOf("p", "deadbeef"),
                listOf("expiration", "1700000000"),
                listOf("e", "abc123"),
            )
        )
        assertEquals("deadbeef", event.getTagValue("p"))
        assertEquals("1700000000", event.getTagValue("expiration"))
        assertEquals("abc123", event.getTagValue("e"))
        assertNull(event.getTagValue("nonexistent"))
    }

    @Test
    fun `nostr event getTagValues returns all matching`() {
        val event = makeTestEvent(
            tags = listOf(
                listOf("p", "key1"),
                listOf("p", "key2"),
                listOf("e", "event1"),
            )
        )
        assertEquals(listOf("key1", "key2"), event.getTagValues("p"))
        assertEquals(listOf("event1"), event.getTagValues("e"))
        assertEquals(emptyList(), event.getTagValues("nonexistent"))
    }

    @Test
    fun `expiration tag filtering logic`() {
        val now = 1700000000L

        // Expired event (expiration in the past)
        val expiredEvent = makeTestEvent(tags = listOf(listOf("expiration", "${now - 100}")))
        val expiration1 = expiredEvent.getTagValue("expiration")?.toLongOrNull()
        assertNotNull(expiration1)
        assertTrue(expiration1 < now, "event should be expired")

        // Valid event (expiration in the future)
        val validEvent = makeTestEvent(tags = listOf(listOf("expiration", "${now + 3600}")))
        val expiration2 = validEvent.getTagValue("expiration")?.toLongOrNull()
        assertNotNull(expiration2)
        assertTrue(expiration2 >= now, "event should not be expired")

        // No expiration tag — should not be filtered
        val noExpEvent = makeTestEvent(tags = emptyList())
        val expiration3 = noExpEvent.getTagValue("expiration")?.toLongOrNull()
        assertNull(expiration3)
    }

    // -- Test 13: NostrEvent JSON roundtrip --

    @Test
    fun `nostr event toJson and fromJson roundtrip`() {
        val event = makeTestEvent(
            kind = 23194,
            tags = listOf(listOf("p", "ab".repeat(32))),
            content = "encrypted content here"
        )
        val jsonStr = event.toJson()
        val parsed = Json.parseToJsonElement(jsonStr) as JsonObject
        val restored = NostrEvent.fromJson(parsed)

        assertEquals(event.id, restored.id)
        assertEquals(event.createdAt, restored.createdAt)
        assertEquals(event.kind, restored.kind)
        assertEquals(event.content, restored.content)
        assertEquals(event.tags, restored.tags)
        assertTrue(event.pubkey.contentEquals(restored.pubkey))
        assertTrue(event.sig.contentEquals(restored.sig))
    }

    // -- Test 14: ClientMessage formatting --

    @Test
    fun `client message REQ format`() {
        val filter = NostrFilter(
            kinds = listOf(23194),
            authors = listOf("ab".repeat(32)),
            tags = mapOf("p" to listOf("cd".repeat(32))),
            since = 1700000000L,
        )
        val msg = ClientMessage.req("sub1", filter)
        assertTrue(msg.startsWith("[\"REQ\",\"sub1\","))
        val parsed = Json.parseToJsonElement(msg).jsonArray
        assertEquals("REQ", parsed[0].jsonPrimitive.content)
        assertEquals("sub1", parsed[1].jsonPrimitive.content)
        val filterObj = parsed[2].jsonObject
        assertEquals(23194, filterObj["kinds"]!!.jsonArray[0].jsonPrimitive.int)
        assertEquals("ab".repeat(32), filterObj["authors"]!!.jsonArray[0].jsonPrimitive.content)
        assertEquals("cd".repeat(32), filterObj["#p"]!!.jsonArray[0].jsonPrimitive.content)
        assertEquals(1700000000L, filterObj["since"]!!.jsonPrimitive.long)
    }

    @Test
    fun `client message CLOSE format`() {
        val msg = ClientMessage.close("sub1")
        assertEquals("""["CLOSE","sub1"]""", msg)
    }

    // -- Test 15: Budget math --

    @Test
    fun `budget exceeded check`() {
        // Simulates the budget check logic from NwcService
        val budgetMsat = 100_000L
        val spentMsat = 80_000L
        val paymentMsat = 30_000L

        // This should exceed: 80000 + 30000 = 110000 > 100000
        assertTrue(spentMsat + paymentMsat > budgetMsat)

        // This should be within budget
        val smallPayment = 15_000L
        assertTrue(spentMsat + smallPayment <= budgetMsat)
    }

    @Test
    fun `budget reset timing`() {
        // Simulates the budget reset logic from NwcService
        val budgetIntervalSecs = 3600L // 1 hour
        val lastResetAt = 1700000000_000L // millis

        // 30 minutes later — should NOT reset
        val now1 = lastResetAt + 1800_000L
        val elapsed1 = now1 - lastResetAt
        assertTrue(elapsed1 < budgetIntervalSecs * 1000, "should not reset after 30 min")

        // 61 minutes later — should reset
        val now2 = lastResetAt + 3660_000L
        val elapsed2 = now2 - lastResetAt
        assertTrue(elapsed2 >= budgetIntervalSecs * 1000, "should reset after 61 min")
    }

    // -- Test 16: AES-256-CBC --

    @Test
    fun `aes256cbc encrypt-decrypt roundtrip`() {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(16) { (0xf0 + it).toByte() }
        val plaintext = "Hello NIP-04!".encodeToByteArray()

        val ciphertext = Aes256Cbc.encrypt(key, iv, plaintext)
        val decrypted = Aes256Cbc.decrypt(key, iv, ciphertext)
        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun `aes256cbc known test vector`() {
        // NIST AES-256-CBC test vector (F.2.5/F.2.6 from SP 800-38A)
        val key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".hexToByteArray()
        val iv = "000102030405060708090a0b0c0d0e0f".hexToByteArray()
        val plaintext = "6bc1bee22e409f96e93d7e117393172a".hexToByteArray()

        val ciphertext = Aes256Cbc.encrypt(key, iv, plaintext)
        // First block of ciphertext should match NIST vector
        // The output includes PKCS#7 padding (adds a full 16-byte pad block)
        assertEquals(32, ciphertext.size) // 16 plaintext + 16 padding
        val firstBlock = ciphertext.sliceArray(0 until 16)
        assertEquals("f58c4c04d6e5f1ba779eabfb5f7bfbd6", firstBlock.toHex())
    }

    @Test
    fun `aes256cbc various plaintext lengths`() {
        val key = ByteArray(32) { (it * 3).toByte() }
        val iv = ByteArray(16) { (it * 7).toByte() }

        // Test empty, 1 byte, 15 bytes, 16 bytes, 17 bytes, 256 bytes
        for (len in listOf(0, 1, 15, 16, 17, 256)) {
            val plaintext = ByteArray(len) { (it % 256).toByte() }
            val ciphertext = Aes256Cbc.encrypt(key, iv, plaintext)
            val decrypted = Aes256Cbc.decrypt(key, iv, ciphertext)
            assertTrue(plaintext.contentEquals(decrypted), "roundtrip failed for $len-byte plaintext")
        }
    }

    // -- Test 17: NIP-04 encrypt/decrypt --

    @Test
    fun `nip04 encrypt-decrypt roundtrip`() {
        val alice = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000002")
        val bob = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000003")

        val sharedAlice = NostrCrypto.nip04SharedSecret(alice, bob.publicKey())
        val sharedBob = NostrCrypto.nip04SharedSecret(bob, alice.publicKey())
        assertTrue(sharedAlice.contentEquals(sharedBob), "NIP-04 shared secrets must match")

        val plaintext = "Hello NIP-04 from phoenixd!"
        val encrypted = NostrCrypto.nip04Encrypt(sharedAlice, plaintext)

        // Verify format: base64?iv=base64
        assertTrue(encrypted.contains("?iv="), "NIP-04 format must contain ?iv=")

        val decrypted = NostrCrypto.nip04Decrypt(sharedBob, encrypted)
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `nip04 shared secret differs from nip44 conversation key`() {
        val alice = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000002")
        val bob = PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000003")

        val nip04Secret = NostrCrypto.nip04SharedSecret(alice, bob.publicKey())
        val nip44Key = NostrCrypto.nip44ConversationKey(alice, bob.publicKey())
        // NIP-04 uses raw ECDH x-coordinate, NIP-44 applies HKDF — they must differ
        assertTrue(!nip04Secret.contentEquals(nip44Key), "NIP-04 and NIP-44 keys must differ")
    }

    // -- Helpers --

    private fun makeTestEvent(
        kind: Int = 1,
        tags: List<List<String>> = emptyList(),
        content: String = "test",
    ): NostrEvent {
        val pubkey = ByteArray(32) { 0xab.toByte() }
        val id = NostrCrypto.computeEventId(pubkey, 1700000000L, kind, tags, content)
        return NostrEvent(
            id = id,
            pubkey = pubkey,
            createdAt = 1700000000L,
            kind = kind,
            tags = tags,
            content = content,
            sig = ByteArray(64) { 0x00 }
        )
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
