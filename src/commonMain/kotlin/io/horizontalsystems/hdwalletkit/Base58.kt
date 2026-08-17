package io.horizontalsystems.hdwalletkit

/** Bitcoin's base58 encoding.  Checksum handling intentionally remains with callers. */
object Base58 {
    private const val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val indexes = IntArray(128) { -1 }.also { table -> alphabet.forEachIndexed { index, c -> table[c.code] = index } }

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""
        val number = input.copyOf()
        val zeros = countLeadingZeros(number)
        val output = CharArray(number.size * 2)
        var outputStart = output.size
        var inputStart = zeros

        while (inputStart < number.size) {
            output[--outputStart] = alphabet[divmod(number, inputStart, 256, 58)]
            if (number[inputStart] == 0.toByte()) inputStart++
        }
        while (outputStart < output.size && output[outputStart] == alphabet[0]) outputStart++
        repeat(zeros) { output[--outputStart] = alphabet[0] }
        return output.concatToString(outputStart, output.size)
    }

    fun decode(value: String): ByteArray {
        if (value.isEmpty()) return ByteArray(0)
        val input = ByteArray(value.length) { index ->
            val code = value[index].code
            val digit = if (code < indexes.size) indexes[code] else -1
            require(digit >= 0) { "Illegal character ${value[index]} at index $index" }
            digit.toByte()
        }
        val zeros = countLeadingZeros(input)
        val decoded = ByteArray(input.size)
        var outputStart = decoded.size
        var inputStart = zeros

        while (inputStart < input.size) {
            decoded[--outputStart] = divmod(input, inputStart, 58, 256).toByte()
            if (input[inputStart] == 0.toByte()) inputStart++
        }
        while (outputStart < decoded.size && decoded[outputStart] == 0.toByte()) outputStart++
        return decoded.copyOfRange(outputStart - zeros, decoded.size)
    }

    private fun countLeadingZeros(number: ByteArray): Int {
        var count = 0
        while (count < number.size && number[count] == 0.toByte()) count++
        return count
    }

    private fun divmod(number: ByteArray, start: Int, base: Int, divisor: Int): Int {
        var remainder = 0
        for (index in start until number.size) {
            val value = remainder * base + (number[index].toInt() and 255)
            number[index] = (value / divisor).toByte()
            remainder = value % divisor
        }
        return remainder
    }
}
