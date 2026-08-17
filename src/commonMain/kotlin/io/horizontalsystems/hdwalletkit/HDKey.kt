package io.horizontalsystems.hdwalletkit

import fr.acinq.secp256k1.Secp256k1

open class HDDerivationException(message: String) : RuntimeException(message)
class CantDeriveNonHardened : HDDerivationException("can't derive non hardened")
sealed class Curve {
    data object Secp256K1 : Curve()
    data object Ed25519 : Curve()
    internal val seedSalt get() = if (this is Ed25519) "ed25519 seed" else "Bitcoin seed"
    internal val supportsPublicDerivation get() = this is Secp256K1
}

class HDKey private constructor(
    privateKey: ByteArray?, pubKey: ByteArray, chainCode: ByteArray, val parent: HDKey?,
    val parentFingerprint: Int, val depth: Int, val childNumber: Int, val isHardened: Boolean
) : ECKey(privateKey, pubKey) {
    private val privateKey = privateKey?.copyOf()
    private val chainCodeBytes = chainCode.copyOf()
    val chainCode: ByteArray get() = chainCodeBytes.copyOf()
    constructor(pubKey: ByteArray, chainCode: ByteArray, parent: HDKey?, parentFingerprint: Int, depth: Int, childNumber: Int, isHardened: Boolean) : this(null, pubKey, chainCode, parent, parentFingerprint, depth, childNumber, isHardened)
    init { require(chainCodeBytes.size == 32); require(pubKey.size == 33) }
    override fun hasPrivKey() = privateKey != null
    fun getChildNumberEncoded(): Int = if (isHardened) childNumber or HARDENED_FLAG else childNumber
    fun getFingerprint(): Int = pubKeyHash.readInt(0)
    fun getPaddedPrivKeyBytes(): ByteArray = byteArrayOf(0) + privKeyBytes
    fun serializePublic(version: Int): String = Base58.encode(addChecksum(serialize(version, pubKey)))
    fun serializePrivate(version: Int): String = Base58.encode(addChecksum(serialize(version, getPaddedPrivKeyBytes())))
    private fun serialize(version: Int, key: ByteArray): ByteArray = version.toBigEndian() + byteArrayOf(depth.toByte()) + parentFingerprint.toBigEndian() + getChildNumberEncoded().toBigEndian() + chainCodeBytes + key
    fun path(): List<Int> = parent?.path().orEmpty() + childNumber
    override fun toString(): String = parent?.let { "$it/$childNumber${if (isHardened) "'" else ""}" } ?: "m"
    companion object {
        const val HARDENED_FLAG = Int.MIN_VALUE
        fun fromPrivate(privateKey: ByteArray, chainCode: ByteArray, parent: HDKey?, parentFingerprint: Int, depth: Int, childNumber: Int, isHardened: Boolean) = HDKey(privateKey, ECKey.pubKeyFromPrivKey(privateKey), chainCode, parent, parentFingerprint, depth, childNumber, isHardened)
        fun addChecksum(input: ByteArray) = input + doubleSha256(input).copyOf(4)
    }
}

object HDKeyDerivation {
    fun createRootKey(seed: ByteArray, curve: Curve): HDKey {
        require(seed.size >= 16) { "Seed must be at least 128 bits" }
        val material = PlatformCrypto.hmacSha512(curve.seedSalt.encodeToByteArray(), seed)
        val secret = material.leftHalf()
        if (curve is Curve.Secp256K1 && !Secp256k1.secKeyVerify(secret)) throw HDDerivationException("Invalid master private key")
        return HDKey.fromPrivate(secret, material.rightHalf(), null, 0, 0, 0, false)
    }
    fun deriveChildKey(parent: HDKey, childNumber: Int, hardened: Boolean, curve: Curve): HDKey {
        require(childNumber and HDKey.HARDENED_FLAG == 0) { "Hardened flag must not be set in child number" }
        if (!hardened && !curve.supportsPublicDerivation) throw CantDeriveNonHardened()
        val data = derivationData(parent, childNumber, hardened)
        val material = PlatformCrypto.hmacSha512(parent.chainCode, data)
        val tweak = material.leftHalf()
        val chainCode = material.rightHalf()
        val private = parent.privateKeyOrNull
        return if (private != null) {
            val child = if (curve is Curve.Ed25519) tweak else privateChild(private, tweak)
            HDKey.fromPrivate(child, chainCode, parent, parent.getFingerprint(), parent.depth + 1, childNumber, hardened)
        } else {
            if (hardened) throw IllegalStateException("Hardened key requires parent private key")
            val child = publicChild(parent.pubKey, tweak)
            HDKey(child, chainCode, parent, parent.getFingerprint(), parent.depth + 1, childNumber, false)
        }
    }

    private fun derivationData(parent: HDKey, childNumber: Int, hardened: Boolean): ByteArray {
        val encodedChildNumber = if (hardened) childNumber or HDKey.HARDENED_FLAG else childNumber
        val parentMaterial = if (hardened) parent.getPaddedPrivKeyBytes() else parent.pubKey
        return parentMaterial + encodedChildNumber.toBigEndian()
    }

    private fun ByteArray.leftHalf(): ByteArray = copyOfRange(0, 32)
    private fun ByteArray.rightHalf(): ByteArray = copyOfRange(32, 64)

    private fun privateChild(parentSecret: ByteArray, tweak: ByteArray): ByteArray = try {
        Secp256k1.privKeyTweakAdd(parentSecret, tweak)
    } catch (error: Throwable) {
        throw HDDerivationException("Invalid derived private key").also { it.initCause(error) }
    }

    private fun publicChild(parentPublicKey: ByteArray, tweak: ByteArray): ByteArray = try {
        Secp256k1.pubKeyCompress(Secp256k1.pubKeyTweakAdd(parentPublicKey, tweak))
    } catch (error: Throwable) {
        throw HDDerivationException("Invalid derived public key").also { it.initCause(error) }
    }
}

class HDKeychain(val hdKey: HDKey, val curve: Curve = Curve.Secp256K1) {
    constructor(seed: ByteArray, curve: Curve = Curve.Secp256K1) : this(HDKeyDerivation.createRootKey(seed, curve), curve)
    fun getKeyByPath(path: String): HDKey {
        if (path == "" || path == "m" || path == "/") return hdKey
        val chunks = path.removePrefix("m/").removePrefix("/").split('/')
        return chunks.fold(hdKey) { key, chunk ->
            val hardened = chunk.endsWith("'")
            val childNumber = chunk.removeSuffix("'").toInt()
            HDKeyDerivation.deriveChildKey(key, childNumber, hardened, curve)
        }
    }
    fun deriveNonHardenedChildKeys(parent: HDKey, indices: IntRange) = indices.map { HDKeyDerivation.deriveChildKey(parent, it, false, curve) }
}
