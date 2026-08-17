package io.horizontalsystems.hdwalletkit

enum class HDExtendedKeyVersion(val value: Int, val base58Prefix: String) {
    xprv(0x0488ade4, "xprv"), xpub(0x0488b21e, "xpub"), yprv(0x049d7878, "yprv"), ypub(0x049d7cb2, "ypub"), zprv(0x04b2430c, "zprv"), zpub(0x04b24746, "zpub"), Ltpv(0x019d9cfe, "Ltpv"), Ltub(0x019da462, "Ltub"), Mtpv(0x01b26792, "Mtpv"), Mtub(0x01b26ef6, "Mtub"), dgpv(0x02fac398, "dgpv"), dgub(0x02facafd, "dgub"), drkv(0x02fe52cc, "drkv"), drkp(0x02fe52f8, "drkp");
    val isPublic get() = this in setOf(xpub, ypub, zpub, Ltub, Mtub, dgub, drkp)
    val pubKey get() = when (this) { xprv -> xpub; yprv -> ypub; zprv -> zpub; Ltpv -> Ltub; Mtpv -> Mtub; dgpv -> dgub; drkv -> drkp; else -> this }
    val privKey get() = if (isPublic) throw IllegalStateException("No privateKey of $base58Prefix") else this
    val purposes get() = when (this) {
        xprv, xpub -> listOf(HDWallet.Purpose.BIP44, HDWallet.Purpose.BIP86)
        Ltpv, Ltub, dgpv, dgub, drkv, drkp -> listOf(HDWallet.Purpose.BIP44)
        yprv, ypub, Mtpv, Mtub -> listOf(HDWallet.Purpose.BIP49)
        zprv, zpub -> listOf(HDWallet.Purpose.BIP84)
    }
    val coinTypes get() = when (this) {
        xprv, xpub, zprv, zpub -> listOf(ExtendedKeyCoinType.Bitcoin, ExtendedKeyCoinType.Litecoin)
        yprv, ypub -> listOf(ExtendedKeyCoinType.Bitcoin)
        Ltpv, Ltub, Mtpv, Mtub -> listOf(ExtendedKeyCoinType.Litecoin)
        dgpv, dgub -> listOf(ExtendedKeyCoinType.Dogecoin)
        drkv, drkp -> listOf(ExtendedKeyCoinType.Dash)
    }
    companion object {
        fun initFrom(purpose: HDWallet.Purpose, coinType: ExtendedKeyCoinType, isPrivate: Boolean): HDExtendedKeyVersion = when (purpose) {
            HDWallet.Purpose.BIP44 -> when (coinType) {
                ExtendedKeyCoinType.Bitcoin -> if (isPrivate) xprv else xpub
                ExtendedKeyCoinType.Litecoin -> if (isPrivate) Ltpv else Ltub
                ExtendedKeyCoinType.Dogecoin -> if (isPrivate) dgpv else dgub
                ExtendedKeyCoinType.Dash -> if (isPrivate) drkv else drkp
            }
            HDWallet.Purpose.BIP49 -> when (coinType) {
                ExtendedKeyCoinType.Bitcoin -> if (isPrivate) yprv else ypub
                ExtendedKeyCoinType.Litecoin -> if (isPrivate) Mtpv else Mtub
                ExtendedKeyCoinType.Dogecoin, ExtendedKeyCoinType.Dash -> throw IllegalStateException("BIP49 not supported for $coinType")
            }
            HDWallet.Purpose.BIP84 -> if (isPrivate) zprv else zpub
            HDWallet.Purpose.BIP86 -> if (isPrivate) xprv else xpub
        }
        fun initFrom(prefix: String) = entries.firstOrNull { it.base58Prefix == prefix }
        fun initFrom(version: ByteArray) = entries.firstOrNull { it.value == version.readInt(0) }
    }
}
enum class ExtendedKeyCoinType { Bitcoin, Litecoin, Dogecoin, Dash }

class HDExtendedKey(val key: HDKey, private val version: HDExtendedKeyVersion) {
    private constructor(parsed: Parsed) : this(parsed.key, parsed.version)
    constructor(serialized: String) : this(parse(serialized))
    constructor(seed: ByteArray, purpose: HDWallet.Purpose, curve: Curve = Curve.Secp256K1) : this(HDKeyDerivation.createRootKey(seed, curve), when (purpose) { HDWallet.Purpose.BIP49 -> HDExtendedKeyVersion.yprv; HDWallet.Purpose.BIP84 -> HDExtendedKeyVersion.zprv; else -> HDExtendedKeyVersion.xprv })
    val derivedType get() = DerivedType.initFrom(key.depth)
    val purposes get() = version.purposes
    val coinTypes get() = version.coinTypes
    val isPublic get() = version.isPublic
    fun serializePublic() = key.serializePublic(version.pubKey.value)
    fun serializePrivate() = key.serializePrivate(version.privKey.value)
    fun serialize() = if (key.hasPrivKey()) serializePrivate() else serializePublic()
    enum class DerivedType {
        Bip32, Master, Account;
        companion object {
            fun initFrom(depth: Int) = when (depth) { 0 -> Master; 3 -> Account; else -> Bip32 }
        }
    }
    sealed class ParsingError : Throwable() { data object WrongVersion : ParsingError(); data object WrongKeyLength : ParsingError(); data object WrongDerivedType : ParsingError(); data object InvalidChecksum : ParsingError() }
    companion object {
        private data class Parsed(val key: HDKey, val version: HDExtendedKeyVersion)
        private fun parse(serialized: String): Parsed {
            val raw = Base58.decode(serialized)
            if (raw.size != SERIALIZED_KEY_SIZE) throw ParsingError.WrongKeyLength

            val payload = raw.copyOfRange(0, PAYLOAD_SIZE)
            validateChecksum(payload, raw.copyOfRange(PAYLOAD_SIZE, SERIALIZED_KEY_SIZE))
            val version = HDExtendedKeyVersion.initFrom(payload.copyOfRange(0, 4)) ?: throw ParsingError.WrongVersion
            val depth = payload[4].toInt() and 255
            val parentFingerprint = payload.readInt(5)
            val sequence = payload.readInt(9)
            val chainCode = payload.copyOfRange(13, 45)
            val keyMaterial = payload.copyOfRange(45, PAYLOAD_SIZE)
            val childNumber = sequence and Int.MAX_VALUE
            val hardened = sequence and HDKey.HARDENED_FLAG != 0

            if (DerivedType.initFrom(depth) == DerivedType.Bip32) throw ParsingError.WrongDerivedType
            val key = if (version.isPublic) {
                HDKey(keyMaterial, chainCode, null, parentFingerprint, depth, childNumber, hardened)
            } else {
                if (keyMaterial[0] != 0.toByte()) throw ParsingError.WrongKeyLength
                HDKey.fromPrivate(keyMaterial.copyOfRange(1, 33), chainCode, null, parentFingerprint, depth, childNumber, hardened)
            }
            return Parsed(key, version)
        }
        fun version(serialized: String) = HDExtendedKeyVersion.initFrom(serialized.take(4)) ?: throw ParsingError.WrongVersion
        fun validate(serialized: String, isPublic: Boolean) {
            val parsed = parse(serialized)
            if (parsed.version.isPublic != isPublic) throw ParsingError.WrongVersion
        }
        fun validateChecksum(extendedKey: ByteArray) {
            if (extendedKey.size < CHECKSUM_SIZE) throw ParsingError.InvalidChecksum
            val payloadSize = extendedKey.size - CHECKSUM_SIZE
            validateChecksum(extendedKey.copyOfRange(0, payloadSize), extendedKey.copyOfRange(payloadSize, extendedKey.size))
        }

        private fun validateChecksum(payload: ByteArray, checksum: ByteArray) {
            if (!doubleSha256(payload).copyOf(CHECKSUM_SIZE).contentEquals(checksum)) {
                throw ParsingError.InvalidChecksum
            }
        }

        private const val PAYLOAD_SIZE = 78
        private const val CHECKSUM_SIZE = 4
        private const val SERIALIZED_KEY_SIZE = PAYLOAD_SIZE + CHECKSUM_SIZE
    }
}
