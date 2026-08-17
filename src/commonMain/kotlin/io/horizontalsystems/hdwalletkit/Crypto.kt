package io.horizontalsystems.hdwalletkit

/** Platform cryptographic digest provider. It is deliberately internal: public wallet APIs are byte-oriented. */
internal expect object PlatformCrypto {
    fun randomBytes(size: Int): ByteArray
    fun sha256(input: ByteArray): ByteArray
    fun hmacSha512(key: ByteArray, input: ByteArray): ByteArray
    fun ripemd160(input: ByteArray): ByteArray
    fun normalizeNfkd(input: String): String
}

internal fun ByteArray.sha256() = PlatformCrypto.sha256(this)
internal fun doubleSha256(input: ByteArray) = input.sha256().sha256()
internal fun hash160(input: ByteArray) = PlatformCrypto.ripemd160(input.sha256())
internal fun taggedHash(tag: String, data: ByteArray): ByteArray = tag.encodeToByteArray().sha256().let { it + it + data }.sha256()

/** BIP-39 PBKDF2-HMAC-SHA512 implemented from the platform HMAC primitive.
 *
 * Android did not expose PBKDF2WithHmacSHA512 until API 26. Keeping the loop
 * here makes the minSdk 24 contract independent of a provider registration.
 */
internal fun pbkdf2HmacSha512(password: ByteArray, salt: ByteArray, rounds: Int, length: Int): ByteArray {
    require(rounds > 0) { "PBKDF2 rounds must be positive" }
    require(length >= 0) { "PBKDF2 length must not be negative" }
    val blocks = (length + 63) / 64
    val output = ByteArray(length)
    for (blockIndex in 1..blocks) {
        var u = PlatformCrypto.hmacSha512(password, salt + blockIndex.toBigEndian())
        val t = u.copyOf()
        repeat(rounds - 1) {
            u = PlatformCrypto.hmacSha512(password, u)
            for (index in t.indices) t[index] = (t[index].toInt() xor u[index].toInt()).toByte()
        }
        val outputOffset = (blockIndex - 1) * 64
        t.copyInto(output, outputOffset, endIndex = minOf(t.size, length - outputOffset))
    }
    return output
}

internal fun Int.toBigEndian(): ByteArray = byteArrayOf((this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), toByte())
internal fun ByteArray.readInt(offset: Int): Int = ((this[offset].toInt() and 255) shl 24) or ((this[offset + 1].toInt() and 255) shl 16) or ((this[offset + 2].toInt() and 255) shl 8) or (this[offset + 3].toInt() and 255)
