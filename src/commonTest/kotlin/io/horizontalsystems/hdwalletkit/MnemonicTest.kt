package io.horizontalsystems.hdwalletkit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class MnemonicTest {

    private val mnemonic = Mnemonic()

    @Test
    fun toMnemonic_knownEntropy_returnsExpectedWords() {
        val entropy = hexStringToByteArray("7787bfe5815e1912a1ec409a56391109")
        val words = mnemonic.toMnemonic(entropy, Language.English).joinToString(separator = " ")
        val expected = "jealous digital west actor thunder matter marble marine olympic range dust banner"
        assertEquals(words, expected)
    }

    @Test
    fun toMnemonic_emptyEntropy_throws() {
        assertFailsWith<Mnemonic.EmptyEntropyException> {
        mnemonic.toMnemonic(hexStringToByteArray(""), Language.English)

        }
    }

    @Test
    fun validate_validEnglish_succeeds() {
        val words = listOf(
            "jealous", "digital", "west", "actor", "thunder", "matter",
            "marble", "marine", "olympic", "range", "dust", "banner"
        )
        mnemonic.validate(words)
    }

    @Test
    fun validate_validSpanish_succeeds() {
        val words = listOf(
            "fresa", "miope", "triste", "bozal", "ética", "risa",
            "virgo", "nariz", "gráfico", "regla", "selva", "uva",
            "olivo", "candil", "servir"
        )
        mnemonic.validate(words)
    }

    @Test
    fun validate_spanishWithDiacriticals_succeeds() {
        val words = listOf(
            "exceso", "tobillo", "cuento", "tapa", "fibra", "rueda",
            "mojar", "gente", "caimán", "coco", "médula", "oculto"
        )
        mnemonic.validate(words)
    }

    @Test
    fun validate_validChinese_succeeds() {
        val words = listOf(
            "搞", "顿", "雏", "百", "跑", "秒",
            "摊", "婚", "父", "迷", "挺", "卢",
            "浪", "目", "吏"
        )
        mnemonic.validate(words)
    }

    @Test
    fun validate_wrongWordCount_throws() {
        assertFailsWith<Mnemonic.InvalidMnemonicCountException> {
        val words = listOf(
            "digital", "west", "actor", "thunder", "matter", "marble",
            "marine", "olympic", "range", "dust", "banner"
        )
        mnemonic.validate(words)

        }
    }

    @Test
    fun validate_wrongWordCountChinese_throws() {
        assertFailsWith<Mnemonic.InvalidMnemonicCountException> {
        val words = listOf(
            "搞", "顿", "雏", "百", "跑", "秒",
            "摊", "婚", "父", "迷", "挺", "卢",
            "浪", "目", "吏", "搞"
        )
        mnemonic.validate(words)

        }
    }

    @Test
    fun validate_invalidWord_throws() {
        assertFailsWith<Mnemonic.InvalidMnemonicKeyException> {
        val words = listOf(
            "jealous", "digitalll", "west", "actor", "thunder", "matter",
            "marble", "marine", "olympic", "range", "dust", "banner"
        )
        mnemonic.validate(words)

        }
    }

    @Test
    fun validate_mixedLanguages_throws() {
        assertFailsWith<Mnemonic.InvalidMnemonicKeyException> {
        val words = listOf(
            "あいこくしん", "digital", "west", "actor", "thunder", "matter",
            "marble", "marine", "olympic", "range", "dust", "banner"
        )
        mnemonic.validate(words)

        }
    }

    @Test
    fun validate_invalidChecksum_throws() {
        assertFailsWith<Mnemonic.ChecksumException> {
        val words = listOf(
            "jealous", "olympic", "digital", "west", "actor", "thunder",
            "matter", "marble", "marine", "range", "dust", "banner"
        )
        mnemonic.validate(words)

        }
    }

    @Test
    fun toSeed_validWords_returnsExpectedSeed() {
        val words = listOf(
            "jealous", "digital", "west", "actor", "thunder", "matter",
            "marble", "marine", "olympic", "range", "dust", "banner"
        )
        val seed = mnemonic.toSeed(words)
        val expected = hexStringToByteArray(
            "6908630f564bd3ca9efb521e72da86727fc78285b15decedb44f40b02474502e" +
            "d6844958b29465246a618b1b56b4bdffacd1de8b324159e0f7f594c611b0519d"
        )
        assertContentEquals(seed, expected)
    }

    @Test
    fun toSeed_wrongWordCount_throws() {
        assertFailsWith<Mnemonic.InvalidMnemonicCountException> {
        val words = listOf(
            "digital", "west", "actor", "thunder", "matter", "marble",
            "marine", "olympic", "range", "dust", "banner"
        )
        mnemonic.toSeed(words)

        }
    }

    @Test
    fun toSeed_invalidWord_throws() {
        assertFailsWith<Mnemonic.InvalidMnemonicKeyException> {
        val words = listOf(
            "jealous", "digitalll", "west", "actor", "thunder", "matter",
            "marble", "marine", "olympic", "range", "dust", "banner"
        )
        mnemonic.validate(words)

        }
    }

    @Test
    fun generate_default_returns12Words() {
        val words = mnemonic.generate()
        assertEquals(12, words.size)
    }

    @Test
    fun generate_24words_returns24Words() {
        val words = mnemonic.generate(Mnemonic.EntropyStrength.VeryHigh)
        assertEquals(24, words.size)
    }

    @Test
    fun generate_result_passesValidation() {
        val words = mnemonic.generate()
        mnemonic.validate(words)
    }

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((s[i].digitToInt(16) shl 4) + s[i + 1].digitToInt(16)).toByte()
            i += 2
        }
        return data
    }
}
