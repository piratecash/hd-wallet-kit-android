package io.horizontalsystems.hdwalletkit.smoke

import io.horizontalsystems.hdwalletkit.ECKey
import io.horizontalsystems.hdwalletkit.ECDSASignature
import io.horizontalsystems.hdwalletkit.HDWallet
import io.horizontalsystems.hdwalletkit.Language
import io.horizontalsystems.hdwalletkit.Mnemonic

/** Compiled by both published Android and Desktop variants. */
object ConsumerSmoke {
    fun exercisePublishedApi(): Boolean {
        val mnemonic = Mnemonic()
        val words = mnemonic.toMnemonic(ByteArray(16), Language.English)
        val wallet = HDWallet(mnemonic.toSeed(words), 0, HDWallet.Purpose.BIP84)
        val key = wallet.privateKey(account = 0, index = 0, external = true)
        val signature = key.createSignature("consumer smoke".encodeToByteArray())
        val digest = ByteArray(32) { 7 }
        // Pcash EVM callers need the 65-byte SEC representation before Keccak hashing.
        val evmPublicKey = key.pubKeyUncompressed
        val ecdsaSignature = ECDSASignature(signature)
        val compactSignature = ecdsaSignature.r + ecdsaSignature.s
        val recovered = ECKey.recoverPublicKeyFromSignature(
            hash = digest,
            compactSignature = compactSignature,
            recoveryId = 0,
            compressed = false
        )
        // Bitcoin Kit's future KMP call shape signs directly with a non-null private scalar.
        val privateScalar: ByteArray = key.privKeyBytes
        val schnorr = key.signSchnorr(digest, ByteArray(32))
        return evmPublicKey.size == 65 && recovered != null && privateScalar.size == 32 &&
            ECKey(key.pubKey).verifySignature("consumer smoke".encodeToByteArray(), signature) && key.verifySchnorr(digest, schnorr)
    }
}
