package io.horizontalsystems.hdwalletkit

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GoldenVectorsTest {
    private fun String.hex() = ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    private val seed = "6908630f564bd3ca9efb521e72da86727fc78285b15decedb44f40b02474502ed6844958b29465246a618b1b56b4bdffacd1de8b324159e0f7f594c611b0519d".hex()

    @Test fun bip39SeedAndBip32PublicDerivation_knownVector_matchesExpectedValues() {
        val words = "jealous digital west actor thunder matter marble marine olympic range dust banner".split(' ')
        assertContentEquals(seed, Mnemonic().toSeed(words))
        assertEquals("xpub6BfAPDy2cSaTkCKVdEw9eJUZ1UbGuu2pbdJ5zoLGHfTRk4vaKW3G2qEQTbR8ZEYAoK6388DxQxurnhaRfnZumhsKwUoT1Rro4EQFq7AhEyB", HDKeychain(seed).getKeyByPath("m/44'/0'/0'").serializePublic(HDExtendedKeyVersion.xpub.value))
    }

    @Test fun bip39Nfkd_publishedVectorAndEquivalentUnicode_matchesExpectedSeed() {
        val words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(' ')
        assertEquals(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            Mnemonic().toSeed(words, "TREZOR").hex()
        )
        assertContentEquals(
            Mnemonic().toSeed(words, "caf\u00e9"),
            Mnemonic().toSeed(words, "cafe\u0301")
        )
    }

    @Test fun bip39Nfkd_japaneseAndKoreanNfcWords_validateAndRestoreSameSeeds() {
        val mnemonic = Mnemonic()
        val japaneseNfkd = mnemonic.toMnemonic(ByteArray(16), Language.Japanese)
        val japaneseNfc = japaneseNfkd.map { if (it == "あおぞら") "あおぞら" else it }
        val koreanNfkd = mnemonic.toMnemonic(ByteArray(16), Language.Korean)
        val koreanNfc = koreanNfkd.map { if (it == "가격") "가격" else it }

        assertTrue(japaneseNfkd.contains("あおぞら"))
        assertTrue(japaneseNfc.contains("あおぞら"))
        assertTrue(koreanNfkd.contains("가격"))
        assertTrue(koreanNfc.contains("가격"))
        mnemonic.validate(japaneseNfkd)
        mnemonic.validate(japaneseNfc)
        mnemonic.validate(koreanNfkd)
        mnemonic.validate(koreanNfc)
        assertContentEquals(mnemonic.toSeed(japaneseNfkd), mnemonic.toSeed(japaneseNfc))
        assertContentEquals(mnemonic.toSeed(koreanNfkd), mnemonic.toSeed(koreanNfc))
    }

    @Test fun ecdsaAndTaproot_knownVectors_matchExpectedValues() {
        val private = "4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64".hex()
        val public = "037d56797fbe9aa506fc263751abf23bb46c9770181a6059096808923f0a64cb15".hex()
        val key = ECKey(public, private, true)
        val transaction = "01000000019cb78e361651edc22c1c6502961440c139038ca8a8d1696392cd002219d796f2000000001976a914e4de5d630c5cacd7af96418a8f35c411c8ff3c0688acffffffff01c0e4022a010000001976a914e4de5d630c5cacd7af96418a8f35c411c8ff3c0688ac0000000001000000".hex()
        assertEquals("304402201d914e9d229e4b8cbb7c8dee96f4fdd835cabae7e016e0859c5dc95977b697d50220681395971eecd5df3eb36b8f97f0c8b1a6e98dc7d5662f921e0b2fb0694db0f2", key.createSignature(transaction).hex())
        assertTrue(key.verifySignature(transaction, key.createSignature(transaction)))
        val receive = HDWallet(HDExtendedKey("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu").key, 0, HDWallet.Purpose.BIP86).privateKey(0, 0, 0)
        assertEquals("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c", receive.tweakedOutputKey.pubKeyXCoord.hex())
    }

    @Test fun derivedKeys_privateChildren_retainSecretsForSigningAndTaproot() {
        val child = HDKeychain(seed).getKeyByPath("m/86'/0'/0'/0/0")
        val message = "derived key secret retention".encodeToByteArray()
        assertTrue(child.hasPrivKey())
        assertTrue(child.verifySignature(message, child.createSignature(message)))
        assertTrue(child.tweakedOutputKey.hasPrivKey())
        assertTrue(child.tweakedOutputKey.verifySignature(message, child.tweakedOutputKey.createSignature(message)))
    }

    @Test fun accountWatchAndExtendedKeyMetadata_legacyMappings_remainCompatible() {
        val account = HDWallet(seed, 0, HDWallet.Purpose.BIP44).privateKey(0)
        val privateAccount = HDWalletAccount(account)
        val watchAccount = HDWalletAccountWatch(HDKey(account.pubKey, account.chainCode, null, account.parentFingerprint, account.depth, account.childNumber, account.isHardened))
        assertContentEquals(privateAccount.publicKey(2, HDWallet.Chain.EXTERNAL).publicKey, watchAccount.publicKey(2, HDWallet.Chain.EXTERNAL).publicKey)
        assertEquals(3, watchAccount.publicKeys(4..6, HDWallet.Chain.INTERNAL).size)
        val extended = HDExtendedKey(account, HDExtendedKeyVersion.xprv)
        assertEquals(HDExtendedKey.DerivedType.Account, extended.derivedType)
        assertEquals(listOf(HDWallet.Purpose.BIP44, HDWallet.Purpose.BIP86), extended.purposes)
        assertEquals(listOf(ExtendedKeyCoinType.Bitcoin, ExtendedKeyCoinType.Litecoin), extended.coinTypes)
        assertEquals(HDExtendedKeyVersion.Mtub, HDExtendedKeyVersion.initFrom(HDWallet.Purpose.BIP49, ExtendedKeyCoinType.Litecoin, false))
        assertEquals(HDExtendedKeyVersion.drkv, HDExtendedKeyVersion.initFrom(HDWallet.Purpose.BIP44, ExtendedKeyCoinType.Dash, true))
        assertEquals(HDExtendedKeyVersion.zpub, HDExtendedKeyVersion.initFrom(HDExtendedKeyVersion.zpub.value.toBigEndian()))
    }

    @Test fun publicKeyCanonicality_supportedSecEncodings_areParsed() {
        val compressed = "037d56797fbe9aa506fc263751abf23bb46c9770181a6059096808923f0a64cb15".hex()
        val uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8".hex()
        assertTrue(ECKey.isPubKeyCanonical(compressed))
        assertTrue(ECKey.isPubKeyCanonical(uncompressed))
        assertFalse(ECKey.isPubKeyCanonical(byteArrayOf(2) + ByteArray(32)))
        assertFalse(ECKey.isPubKeyCanonical(ByteArray(65)))
    }

    @Test fun ecdsaSignature_derRoundTrip_preservesByteComponents() {
        val key = ECKey.fromPrivate("4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64".hex())
        val signature = key.createECDSASignature("signature representation".encodeToByteArray())

        val decoded = ECDSASignature(signature.encodeToDER())

        assertContentEquals(signature.r, decoded.r)
        assertContentEquals(signature.s, decoded.s)
        assertContentEquals(signature.toCompactSignature(), decoded.toCompactSignature())
    }

    @Test fun signatureCanonical_derWithOneSighashByte_matchesLegacyContract() {
        val der = ECKey.fromPrivate("4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64".hex())
            .createSignature("canonical signature".encodeToByteArray())
        val canonical = der + byteArrayOf(1)
        val malformed = der.copyOf().also { it[0] = 0x31 } + byteArrayOf(1)

        assertTrue(ECKey.isSignatureCanonical(canonical))
        assertFalse(ECKey.isSignatureCanonical(der))
        assertFalse(ECKey.isSignatureCanonical(malformed))
        assertFalse(ECKey.isSignatureCanonical(canonical + byteArrayOf(0)))
    }

    @Test fun ecKey_generatedKey_hasPrivateKeyAndSupportsEqualityByPublicKey() {
        val generated = ECKey()

        assertTrue(generated.hasPrivKey())
        assertTrue(generated.privKeyBytes.isNotEmpty())
        assertEquals(generated, ECKey.fromPublicOnly(generated.pubKey))
    }

    @Test fun publicKeyCompressed_uncompressedValidKey_returnsFalseAndMalformedKeyThrows() {
        val uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8".hex()

        assertFalse(ECKey.isPubKeyCompressed(uncompressed))
        assertFailsWith<IllegalArgumentException> { ECKey.isPubKeyCompressed(byteArrayOf(2) + ByteArray(32)) }
    }

    @Test fun keyMaterial_uncompressedRecoveryAndSchnorr_preserveCommonContracts() {
        val privateKey = "4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64".hex()
        val key = ECKey.fromPrivate(privateKey, compressed = false)
        val message = ByteArray(32) { 42 }
        val compact = key.createECDSASignature(message).toCompactSignature()

        assertFalse(key.isCompressed())
        assertEquals(65, key.pubKey.size)
        assertContentEquals(key.pubKeyUncompressed, key.pubKey)
        assertContentEquals(key.pubKeyCompressed, ECKey.pubKeyFromPrivKey(privateKey))
        assertTrue(key.verifySchnorr(message, key.signSchnorr(message, ByteArray(32))))
        assertTrue((0..3).any { ECKey.recoverPublicKeyFromSignature(doubleSha256(message), compact, it, false)?.contentEquals(key.pubKeyUncompressed) == true })
    }

    @Test fun pubKeyHash_compressedAndUncompressedKeys_matchLegacyCompressedHash() {
        val privateKey = "4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64".hex()
        val compressed = ECKey.fromPrivate(privateKey, compressed = true)
        val uncompressed = ECKey.fromPrivate(privateKey, compressed = false)

        assertContentEquals(hash160(compressed.pubKey), compressed.pubKeyHash)
        assertContentEquals(compressed.pubKeyHash, uncompressed.pubKeyHash)
        assertEquals("e4de5d630c5cacd7af96418a8f35c411c8ff3c06", uncompressed.pubKeyHash.hex())
    }

    @Test fun byteAccessors_mutationDoesNotChangeKeyDerivationOrSignature() {
        val key = ECKey.fromPrivate("4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64".hex())
        val originalPublicKey = key.pubKey
        key.pubKey[1] = 0
        key.privKeyBytes[0] = 0
        assertContentEquals(originalPublicKey, key.pubKey)
        assertTrue(key.verifySignature("immutable".encodeToByteArray(), key.createSignature("immutable".encodeToByteArray())))

        val hdKey = HDKeychain(seed).hdKey
        val chainCode = hdKey.chainCode
        chainCode[0] = (chainCode[0].toInt() xor 1).toByte()
        assertFalse(chainCode.contentEquals(hdKey.chainCode))
        val signature = key.createECDSASignature("components".encodeToByteArray())
        val r = signature.r
        r[0] = (r[0].toInt() xor 1).toByte()
        assertFalse(r.contentEquals(signature.r))
    }

    @Test fun deriveChildKey_ed25519NonHardened_throwsTypedDerivationException() {
        val root = HDKeyDerivation.createRootKey(seed, Curve.Ed25519)

        assertFailsWith<CantDeriveNonHardened> {
            HDKeyDerivation.deriveChildKey(root, 0, false, Curve.Ed25519)
        }
    }
}
