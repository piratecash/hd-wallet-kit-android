package io.horizontalsystems.hdwalletkit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class HDKeychainTest {

    val seed = "6908630f564bd3ca9efb521e72da86727fc78285b15decedb44f40b02474502ed6844958b29465246a618b1b56b4bdffacd1de8b324159e0f7f594c611b0519d".hexStringToByteArray()
    val hdKeyManager = HDKeychain(seed, Curve.Secp256K1)

    @Test
    fun getKeyByPath_Bip32() {
        val path32 = "m/0"
        val hdKey = hdKeyManager.getKeyByPath(path32)

        assertEquals(path32, hdKey.toString())
    }

    @Test
    fun getKeyByPath_Bip44() {
        val path44 = "m/44'/0'/0'/0"
        val hdKey = hdKeyManager.getKeyByPath(path44)

        assertEquals(path44, hdKey.toString())
    }

    @Test
    fun getPublicExtendedKey_Bip44() {
        val path44 = "m/44'/0'/0'"
        val hdKey = hdKeyManager.getKeyByPath(path44)
        val base58 = hdKey.serializePublic(HDExtendedKeyVersion.xpub.value)
        val expected = "xpub6BfAPDy2cSaTkCKVdEw9eJUZ1UbGuu2pbdJ5zoLGHfTRk4vaKW3G2qEQTbR8ZEYAoK6388DxQxurnhaRfnZumhsKwUoT1Rro4EQFq7AhEyB"

        assertEquals(expected, base58)
    }

    @Test
    fun getPrivateKeyByPath_invalidPath() {
        assertFailsWith<NumberFormatException> {
            hdKeyManager.getKeyByPath("m/0/b")
        }
    }

}
