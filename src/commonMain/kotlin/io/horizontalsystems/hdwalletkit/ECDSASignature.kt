package io.horizontalsystems.hdwalletkit

import fr.acinq.secp256k1.Secp256k1

/** Byte-oriented ECDSA signature components, each encoded as a 32-byte unsigned scalar. */
class ECDSASignature private constructor(r: ByteArray, s: ByteArray) {
    private val rBytes = r.copyOf()
    private val sBytes = s.copyOf()
    val r: ByteArray get() = rBytes.copyOf()
    val s: ByteArray get() = sBytes.copyOf()

    init {
        require(r.size == COMPONENT_SIZE && s.size == COMPONENT_SIZE) { "ECDSA components must be 32 bytes" }
    }

    private constructor(compact: ByteArray, compactEncoding: Unit) : this(
        compact.copyOfRange(0, COMPONENT_SIZE),
        compact.copyOfRange(COMPONENT_SIZE, COMPONENT_SIZE * 2)
    ) {
        compactEncoding.hashCode()
        require(compact.size == COMPONENT_SIZE * 2) { "Compact ECDSA signatures must be 64 bytes" }
    }

    constructor(der: ByteArray) : this(decodeDer(der), Unit)

    fun encodeToDER(): ByteArray = Secp256k1.compact2der(toCompactSignature())

    fun toCompactSignature(): ByteArray = rBytes + sBytes

    override fun equals(other: Any?): Boolean = other is ECDSASignature && rBytes.contentEquals(other.rBytes) && sBytes.contentEquals(other.sBytes)

    override fun hashCode(): Int = 31 * rBytes.contentHashCode() + sBytes.contentHashCode()

    companion object {
        private const val COMPONENT_SIZE = 32

        fun fromCompact(compact: ByteArray): ECDSASignature {
            require(compact.size == COMPONENT_SIZE * 2) { "Compact ECDSA signatures must be 64 bytes" }
            return ECDSASignature(compact, Unit)
        }

        private fun decodeDer(der: ByteArray): ByteArray = try {
            Secp256k1.der2compact(der)
        } catch (error: Throwable) {
            throw ECException("Unable to decode signature", error)
        }
    }
}
