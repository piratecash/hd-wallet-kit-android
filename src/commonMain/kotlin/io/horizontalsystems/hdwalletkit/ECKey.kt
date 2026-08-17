package io.horizontalsystems.hdwalletkit

import fr.acinq.secp256k1.Secp256k1
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class ECException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** Platform-neutral secp256k1 key with defensive byte-oriented boundaries. */
open class ECKey protected constructor(secret: ByteArray?, suppliedPublic: ByteArray) {
    private val secretBytes = secret?.copyOf()
    private val uncompressedPublicKey = Secp256k1.pubkeyParse(suppliedPublic).copyOf()
    private val compressedPublicKey = Secp256k1.pubKeyCompress(uncompressedPublicKey).copyOf()
    private val compressedEncoding = suppliedPublic.size == COMPRESSED_SIZE

    init {
        secretBytes?.let { privateKey ->
            requireSecret(privateKey)
            require(Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(privateKey)).contentEquals(compressedPublicKey)) {
                "Public key does not match private key"
            }
        }
    }

    /** Requested SEC encoding, copied for every caller. */
    val pubKey: ByteArray get() = if (compressedEncoding) compressedPublicKey.copyOf() else uncompressedPublicKey.copyOf()
    val pubKeyCompressed: ByteArray get() = compressedPublicKey.copyOf()
    val pubKeyUncompressed: ByteArray get() = uncompressedPublicKey.copyOf()
    /** Private-only accessor. It never returns null; public-only keys fail explicitly. */
    open val privKeyBytes: ByteArray get() = secretBytes?.copyOf() ?: throw IllegalStateException("No private key available")
    /** Explicit nullable accessor for flows that accept public-only keys. */
    open val privateKeyOrNull: ByteArray? get() = secretBytes?.copyOf()
    val pubKeyHash: ByteArray get() = hash160(compressedPublicKey)
    val pubKeyXCoord: ByteArray get() = compressedPublicKey.copyOfRange(1, 33)

    private constructor(material: KeyMaterial) : this(material.secret, material.publicKey)
    constructor() : this(newKeyMaterial())
    constructor(pubKey: ByteArray) : this(null, pubKey)
    constructor(pubKey: ByteArray, privateKey: ByteArray, compressed: Boolean) : this(requireSecret(privateKey), selectEncoding(pubKey, compressed))

    open fun hasPrivKey(): Boolean = secretBytes != null
    fun isCompressed(): Boolean = compressedEncoding
    fun createECDSASignature(contents: ByteArray): ECDSASignature = ECDSASignature.fromCompact(signCompact(doubleSha256(contents)))
    fun createSignature(contents: ByteArray): ByteArray = createECDSASignature(contents).encodeToDER()
    fun verifySignature(contents: ByteArray?, signature: ByteArray): Boolean = try {
        val hash = contents?.let(::doubleSha256) ?: ByteArray(32).also { it[0] = 1 }
        Secp256k1.verify(Secp256k1.der2compact(signature), hash, compressedPublicKey)
    } catch (_: Throwable) {
        false
    }

    fun signSchnorr(message: ByteArray, auxRand: ByteArray = ByteArray(32)): ByteArray {
        require(message.size == 32) { "Schnorr messages must be 32 bytes" }
        require(auxRand.size == 32) { "Schnorr auxiliary randomness must be 32 bytes" }
        return Secp256k1.signSchnorr(message, privKeyBytes, auxRand)
    }

    fun verifySchnorr(message: ByteArray, signature: ByteArray): Boolean =
        message.size == 32 && signature.size == 64 && Secp256k1.verifySchnorr(signature, message, pubKeyXCoord)

    @OptIn(ExperimentalEncodingApi::class)
    fun signMessage(message: String): String {
        val header = "Bitcoin Signed Message:\n".encodeToByteArray()
        val messageBytes = message.encodeToByteArray()
        val body = Utils.encode(header.size.toLong()) + header + Utils.encode(messageBytes.size.toLong()) + messageBytes
        val hash = doubleSha256(body)
        val compact = signCompact(hash)
        val publicKey = pubKey
        val recovery = (0..3).firstOrNull { recoveryId ->
            recoverPublicKeyFromSignature(hash, compact, recoveryId, compressedEncoding)?.contentEquals(publicKey) == true
        } ?: throw ECException("Unable to recover public key")
        val compressionOffset = if (compressedEncoding) 4 else 0
        return Base64.encode(byteArrayOf((27 + recovery + compressionOffset).toByte()) + compact)
    }

    val tweakedOutputKey: ECKey get() {
        val internal = byteArrayOf(2) + pubKeyXCoord
        val tweak = taggedHash("TapTweak", pubKeyXCoord)
        val output = Secp256k1.pubKeyCompress(Secp256k1.pubKeyTweakAdd(internal, tweak))
        val privateOutput = secretBytes?.let { privateKey ->
            val normalized = if (Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(privateKey)).contentEquals(internal)) privateKey else Secp256k1.privKeyNegate(privateKey)
            Secp256k1.privKeyTweakAdd(normalized, tweak)
        }
        return if (privateOutput == null) ECKey(output) else ECKey(output, privateOutput, true)
    }

    private fun signCompact(hash: ByteArray): ByteArray = Secp256k1.sign(hash, privKeyBytes)

    override fun equals(other: Any?): Boolean = other is ECKey && compressedPublicKey.contentEquals(other.compressedPublicKey)
    override fun hashCode(): Int = compressedPublicKey.contentHashCode()
    override fun toString(): String = pubKey.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    companion object {
        private const val COMPRESSED_SIZE = 33
        private class KeyMaterial(val secret: ByteArray, val publicKey: ByteArray)

        fun fromPublicOnly(pub: ByteArray): ECKey = ECKey(pub)
        fun fromPrivate(priv: ByteArray, compressed: Boolean = true): ECKey {
            val uncompressed = Secp256k1.pubkeyCreate(requireSecret(priv))
            return ECKey(if (compressed) Secp256k1.pubKeyCompress(uncompressed) else uncompressed, priv, compressed)
        }
        fun pubKeyFromPrivKey(priv: ByteArray, compressed: Boolean = true): ByteArray {
            val uncompressed = Secp256k1.pubkeyCreate(requireSecret(priv))
            return if (compressed) Secp256k1.pubKeyCompress(uncompressed) else uncompressed.copyOf()
        }
        fun recoverPublicKeyFromSignature(hash: ByteArray, compactSignature: ByteArray, recoveryId: Int, compressed: Boolean = true): ByteArray? = try {
            require(hash.size == 32 && compactSignature.size == 64 && recoveryId in 0..3)
            val uncompressed = Secp256k1.ecdsaRecover(compactSignature, hash, recoveryId)
            if (compressed) Secp256k1.pubKeyCompress(uncompressed) else uncompressed
        } catch (_: Throwable) {
            null
        }
        fun isPubKeyCanonical(pub: ByteArray): Boolean = parsePublicKey(pub) != null
        fun isPubKeyCompressed(pub: ByteArray): Boolean {
            val parsed = parsePublicKey(pub) ?: throw IllegalArgumentException("Invalid SEC public key")
            return pub.size == COMPRESSED_SIZE && Secp256k1.pubKeyCompress(parsed).contentEquals(pub)
        }
        fun isSignatureCanonical(signature: ByteArray): Boolean = try {
            val der = signature.copyOf(signature.lastIndex)
            Secp256k1.compact2der(Secp256k1.der2compact(der)).contentEquals(der)
        } catch (_: Throwable) {
            false
        }
        private fun selectEncoding(publicKey: ByteArray, compressed: Boolean): ByteArray {
            val parsed = Secp256k1.pubkeyParse(publicKey)
            return if (compressed) Secp256k1.pubKeyCompress(parsed) else parsed
        }
        private fun parsePublicKey(publicKey: ByteArray): ByteArray? {
            if (publicKey.size != COMPRESSED_SIZE && publicKey.size != 65) return null
            return try { Secp256k1.pubkeyParse(publicKey) } catch (_: Throwable) { null }
        }
        private fun newKeyMaterial(): KeyMaterial {
            while (true) {
                val candidate = PlatformCrypto.randomBytes(32)
                if (Secp256k1.secKeyVerify(candidate)) return KeyMaterial(candidate, Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(candidate)))
            }
        }
        private fun requireSecret(value: ByteArray): ByteArray {
            require(value.size == 32 && Secp256k1.secKeyVerify(value)) { "Invalid secp256k1 private key" }
            return value.copyOf()
        }
    }
}
