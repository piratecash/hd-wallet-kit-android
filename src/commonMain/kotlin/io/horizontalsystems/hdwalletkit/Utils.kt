package io.horizontalsystems.hdwalletkit

object Utils {
    fun doubleDigest(input: ByteArray): ByteArray = doubleSha256(input)
    fun doubleDigest(input: ByteArray, offset: Int, length: Int): ByteArray = doubleSha256(input.copyOfRange(offset, offset + length))
    fun sha256Hash160(input: ByteArray): ByteArray = hash160(input)
    fun hmacSha512(key: ByteArray, input: ByteArray): ByteArray = PlatformCrypto.hmacSha512(key, input)
    fun sha256(input: ByteArray): ByteArray = input.sha256()
    fun sha256(input: ByteArray, offset: Int, length: Int): ByteArray = input.copyOfRange(offset, offset + length).sha256()
    fun taggedHash(tag: String, message: ByteArray): ByteArray = io.horizontalsystems.hdwalletkit.taggedHash(tag, message)
    fun checkBitLE(data: ByteArray, index: Int): Boolean = data[index ushr 3].toInt() and (1 shl (index and 7)) != 0
    fun setBitLE(data: ByteArray, index: Int) { data[index ushr 3] = (data[index ushr 3].toInt() or (1 shl (index and 7))).toByte() }
    fun doubleDigestTwoBuffers(first: ByteArray, firstOffset: Int, firstLength: Int, second: ByteArray, secondOffset: Int, secondLength: Int): ByteArray =
        doubleSha256(first.copyOfRange(firstOffset, firstOffset + firstLength) + second.copyOfRange(secondOffset, secondOffset + secondLength))
    fun readUint32BE(bytes: ByteArray, offset: Int): Long = bytes.readInt(offset).toLong() and 0xffff_ffffL
    fun intToByteArray(value: Int): ByteArray = value.toBigEndian()
    fun encode(value: Long): ByteArray = when {
        value and -0x1_0000_0000L != 0L -> ByteArray(9).also { it[0] = 255.toByte(); uint64ToByteArrayLE(value, it, 1) }
        value and 0xffff_0000L != 0L -> ByteArray(5).also { it[0] = 254.toByte(); uint32ToByteArrayLE(value, it, 1) }
        value >= 253 -> byteArrayOf(253.toByte(), value.toByte(), (value ushr 8).toByte())
        else -> byteArrayOf(value.toByte())
    }
    fun uint32ToByteArrayLE(value: Long, out: ByteArray, offset: Int) { repeat(4) { out[offset + it] = (value ushr (8 * it)).toByte() } }
    fun uint64ToByteArrayLE(value: Long, out: ByteArray, offset: Int) { repeat(8) { out[offset + it] = (value ushr (8 * it)).toByte() } }
}
