package io.horizontalsystems.hdwalletkit

class HDWallet(private val hdKeychain: HDKeychain, private val coinType: Int, purpose: Purpose) {
    constructor(seed: ByteArray, coinType: Int, purpose: Purpose, curve: Curve = Curve.Secp256K1) : this(HDKeychain(seed, curve), coinType, purpose)
    constructor(masterKey: HDKey, coinType: Int, purpose: Purpose, curve: Curve = Curve.Secp256K1) : this(HDKeychain(masterKey, curve), coinType, purpose)
    enum class Chain { EXTERNAL, INTERNAL }
    enum class Purpose(val value: Int) { BIP44(44), BIP49(49), BIP84(84), BIP86(86) }
    val masterKey get() = hdKeychain.hdKey
    private val purpose = purpose.value
    fun hdPublicKey(account: Int, index: Int, external: Boolean) = HDPublicKey(privateKey(account, index, if (external) 0 else 1))
    fun hdPublicKeys(account: Int, indices: IntRange, external: Boolean): List<HDPublicKey> = hdKeychain.deriveNonHardenedChildKeys(privateKey("m/$purpose'/$coinType'/$account'/${if (external) 0 else 1}"), indices).map(::HDPublicKey)
    fun receiveHDPublicKey(account: Int, index: Int) = hdPublicKey(account, index, true)
    fun changeHDPublicKey(account: Int, index: Int) = hdPublicKey(account, index, false)
    fun privateKey(account: Int, index: Int, chain: Int) = privateKey("m/$purpose'/$coinType'/$account'/$chain/$index")
    fun privateKey(account: Int) = privateKey("m/$purpose'/$coinType'/$account'")
    fun privateKey(account: Int, index: Int, external: Boolean) = privateKey(account, index, if (external) 0 else 1)
    fun privateKey(path: String) = hdKeychain.getKeyByPath(path)
}

class HDPublicKey(key: HDKey) { val publicKey = key.pubKey; val publicKeyHash = key.pubKeyHash }
