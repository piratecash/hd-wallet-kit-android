package io.horizontalsystems.hdwalletkit

class HDWalletAccount(accountPrivateKey: HDKey, curve: Curve = Curve.Secp256K1) {
    private val hdKeychain = HDKeychain(accountPrivateKey, curve)

    fun privateKey(index: Int, chain: HDWallet.Chain): HDKey = when (hdKeychain.curve) {
        Curve.Ed25519 -> throw CantDeriveNonHardened()
        Curve.Secp256K1 -> hdKeychain.getKeyByPath("${chain.ordinal}/$index")
    }

    fun privateKey(path: String): HDKey = hdKeychain.getKeyByPath(path)

    fun publicKey(index: Int, chain: HDWallet.Chain): HDPublicKey = HDPublicKey(privateKey(index, chain))

    fun publicKeys(indices: IntRange, chain: HDWallet.Chain): List<HDPublicKey> = when (hdKeychain.curve) {
        Curve.Ed25519 -> throw CantDeriveNonHardened()
        Curve.Secp256K1 -> hdKeychain.deriveNonHardenedChildKeys(privateKey("${chain.ordinal}"), indices).map(::HDPublicKey)
    }
}

class HDWalletAccountWatch(accountPublicKey: HDKey, curve: Curve = Curve.Secp256K1) {
    private val hdKeychain = HDKeychain(accountPublicKey, curve)

    fun publicKey(index: Int, chain: HDWallet.Chain): HDPublicKey = HDPublicKey(hdKeychain.getKeyByPath("${chain.ordinal}/$index"))

    fun publicKeys(indices: IntRange, chain: HDWallet.Chain): List<HDPublicKey> {
        require(indices.first >= 0 && indices.last >= 0) {
            "Derivation error: Can't derive hardened children from public key"
        }
        return hdKeychain.deriveNonHardenedChildKeys(hdKeychain.getKeyByPath("${chain.ordinal}"), indices).map(::HDPublicKey)
    }
}
