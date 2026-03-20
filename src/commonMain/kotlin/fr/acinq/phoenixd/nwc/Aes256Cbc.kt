package fr.acinq.phoenixd.nwc

/**
 * Minimal pure-Kotlin AES-256-CBC implementation for NIP-04.
 * Only used for small Nostr event payloads — not for bulk data.
 */
object Aes256Cbc {

    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32) { "AES-256 key must be 32 bytes" }
        require(iv.size == 16) { "IV must be 16 bytes" }
        val padded = pkcs7Pad(plaintext)
        val expandedKey = expandKey(key)
        val blocks = padded.size / 16
        val output = ByteArray(padded.size)
        var prev = iv.copyOf()
        for (b in 0 until blocks) {
            val block = padded.sliceArray(b * 16 until (b + 1) * 16)
            // XOR with previous ciphertext (or IV)
            for (i in 0 until 16) block[i] = (block[i].toInt() xor prev[i].toInt()).toByte()
            val encrypted = encryptBlock(block, expandedKey)
            encrypted.copyInto(output, b * 16)
            prev = encrypted
        }
        return output
    }

    fun decrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(key.size == 32) { "AES-256 key must be 32 bytes" }
        require(iv.size == 16) { "IV must be 16 bytes" }
        require(ciphertext.size % 16 == 0) { "ciphertext must be multiple of 16 bytes" }
        val expandedKey = expandKey(key)
        val blocks = ciphertext.size / 16
        val output = ByteArray(ciphertext.size)
        var prev = iv.copyOf()
        for (b in 0 until blocks) {
            val block = ciphertext.sliceArray(b * 16 until (b + 1) * 16)
            val decrypted = decryptBlock(block, expandedKey)
            for (i in 0 until 16) decrypted[i] = (decrypted[i].toInt() xor prev[i].toInt()).toByte()
            decrypted.copyInto(output, b * 16)
            prev = block
        }
        return pkcs7Unpad(output)
    }

    // -- PKCS#7 Padding --

    private fun pkcs7Pad(data: ByteArray): ByteArray {
        val padLen = 16 - (data.size % 16)
        return data + ByteArray(padLen) { padLen.toByte() }
    }

    private fun pkcs7Unpad(data: ByteArray): ByteArray {
        val padLen = data.last().toInt() and 0xFF
        require(padLen in 1..16) { "invalid PKCS#7 padding" }
        for (i in data.size - padLen until data.size) {
            require((data[i].toInt() and 0xFF) == padLen) { "invalid PKCS#7 padding" }
        }
        return data.copyOf(data.size - padLen)
    }

    // -- AES Core --

    private val SBOX = intArrayOf(
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    )

    private val INV_SBOX = IntArray(256).also { inv ->
        for (i in SBOX.indices) inv[SBOX[i]] = i
    }

    private val RCON = intArrayOf(
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    )

    // GF(2^8) multiplication
    private fun gmul(a: Int, b: Int): Int {
        var p = 0; var aa = a; var bb = b
        for (i in 0 until 8) {
            if (bb and 1 != 0) p = p xor aa
            val hi = aa and 0x80
            aa = (aa shl 1) and 0xFF
            if (hi != 0) aa = aa xor 0x1b
            bb = bb shr 1
        }
        return p
    }

    private fun expandKey(key: ByteArray): IntArray {
        // AES-256: 14 rounds, 60 words
        val w = IntArray(60)
        for (i in 0 until 8) {
            w[i] = ((key[4*i].toInt() and 0xFF) shl 24) or
                    ((key[4*i+1].toInt() and 0xFF) shl 16) or
                    ((key[4*i+2].toInt() and 0xFF) shl 8) or
                    (key[4*i+3].toInt() and 0xFF)
        }
        for (i in 8 until 60) {
            var temp = w[i - 1]
            if (i % 8 == 0) {
                // RotWord + SubWord + Rcon
                temp = ((SBOX[(temp shr 16) and 0xFF] shl 24) or
                        (SBOX[(temp shr 8) and 0xFF] shl 16) or
                        (SBOX[temp and 0xFF] shl 8) or
                        SBOX[(temp shr 24) and 0xFF])
                temp = temp xor (RCON[i / 8 - 1] shl 24)
            } else if (i % 8 == 4) {
                temp = ((SBOX[(temp shr 24) and 0xFF] shl 24) or
                        (SBOX[(temp shr 16) and 0xFF] shl 16) or
                        (SBOX[(temp shr 8) and 0xFF] shl 8) or
                        SBOX[temp and 0xFF])
            }
            w[i] = w[i - 8] xor temp
        }
        return w
    }

    private fun encryptBlock(input: ByteArray, w: IntArray): ByteArray {
        val state = Array(4) { r -> IntArray(4) { c -> input[r + 4 * c].toInt() and 0xFF } }

        // AddRoundKey(0)
        addRoundKey(state, w, 0)

        for (round in 1..13) {
            subBytes(state)
            shiftRows(state)
            mixColumns(state)
            addRoundKey(state, w, round)
        }

        // Final round (no MixColumns)
        subBytes(state)
        shiftRows(state)
        addRoundKey(state, w, 14)

        return ByteArray(16) { state[it % 4][it / 4].toByte() }
    }

    private fun decryptBlock(input: ByteArray, w: IntArray): ByteArray {
        val state = Array(4) { r -> IntArray(4) { c -> input[r + 4 * c].toInt() and 0xFF } }

        addRoundKey(state, w, 14)

        for (round in 13 downTo 1) {
            invShiftRows(state)
            invSubBytes(state)
            addRoundKey(state, w, round)
            invMixColumns(state)
        }

        invShiftRows(state)
        invSubBytes(state)
        addRoundKey(state, w, 0)

        return ByteArray(16) { state[it % 4][it / 4].toByte() }
    }

    // -- AES Operations --

    private fun addRoundKey(state: Array<IntArray>, w: IntArray, round: Int) {
        for (c in 0..3) {
            val word = w[round * 4 + c]
            state[0][c] = state[0][c] xor ((word shr 24) and 0xFF)
            state[1][c] = state[1][c] xor ((word shr 16) and 0xFF)
            state[2][c] = state[2][c] xor ((word shr 8) and 0xFF)
            state[3][c] = state[3][c] xor (word and 0xFF)
        }
    }

    private fun subBytes(state: Array<IntArray>) {
        for (r in 0..3) for (c in 0..3) state[r][c] = SBOX[state[r][c]]
    }

    private fun invSubBytes(state: Array<IntArray>) {
        for (r in 0..3) for (c in 0..3) state[r][c] = INV_SBOX[state[r][c]]
    }

    private fun shiftRows(state: Array<IntArray>) {
        // Row 1: shift left 1
        val t1 = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t1
        // Row 2: shift left 2
        var t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t; t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t
        // Row 3: shift left 3 (= shift right 1)
        val t3 = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t3
    }

    private fun invShiftRows(state: Array<IntArray>) {
        val t1 = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t1
        var t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t; t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t
        val t3 = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t3
    }

    private fun mixColumns(state: Array<IntArray>) {
        for (c in 0..3) {
            val s0 = state[0][c]; val s1 = state[1][c]; val s2 = state[2][c]; val s3 = state[3][c]
            state[0][c] = gmul(2, s0) xor gmul(3, s1) xor s2 xor s3
            state[1][c] = s0 xor gmul(2, s1) xor gmul(3, s2) xor s3
            state[2][c] = s0 xor s1 xor gmul(2, s2) xor gmul(3, s3)
            state[3][c] = gmul(3, s0) xor s1 xor s2 xor gmul(2, s3)
        }
    }

    private fun invMixColumns(state: Array<IntArray>) {
        for (c in 0..3) {
            val s0 = state[0][c]; val s1 = state[1][c]; val s2 = state[2][c]; val s3 = state[3][c]
            state[0][c] = gmul(14, s0) xor gmul(11, s1) xor gmul(13, s2) xor gmul(9, s3)
            state[1][c] = gmul(9, s0) xor gmul(14, s1) xor gmul(11, s2) xor gmul(13, s3)
            state[2][c] = gmul(13, s0) xor gmul(9, s1) xor gmul(14, s2) xor gmul(11, s3)
            state[3][c] = gmul(11, s0) xor gmul(13, s1) xor gmul(9, s2) xor gmul(14, s3)
        }
    }
}
