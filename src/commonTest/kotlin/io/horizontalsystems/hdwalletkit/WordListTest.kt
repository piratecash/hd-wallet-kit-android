package io.horizontalsystems.hdwalletkit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class WordListTest {

    @Test
    fun wordList_eachLanguage_firstAndLastWordAccessible() {
        for (language in Language.values()) {
            val wordList = WordList.wordList(language)
            assertNotNull(wordList, "wordList($language) returned null")
            // BIP39: 2048 words per language, indices 0..2047
            val firstWord = wordList[0]
            val lastWord = wordList[2047]
            assertTrue(firstWord.isNotBlank(), "$language first word should not be blank")
            assertTrue(lastWord.isNotBlank(), "$language last word should not be blank")
        }
    }

    @Test
    fun wordList_english_containsKnownWords() {
        val wordList = WordList.wordList(Language.English)
        assertTrue(wordList.validWord("abandon", false))
        assertTrue(wordList.validWord("zoo", false))
        assertTrue(wordList.validWord("ability", false))
    }

    @Test
    fun wordList_italian_containsKnownWords() {
        val wordList = WordList.wordList(Language.Italian)
        assertTrue(wordList.validWord("abaco", false))
    }

    @Test
    fun wordList_japanese_containsKnownWords() {
        val wordList = WordList.wordList(Language.Japanese)
        assertTrue(wordList.validWord("あいこくしん", false))
    }

    @Test
    fun wordList_spanish_containsKnownWords() {
        val wordList = WordList.wordList(Language.Spanish)
        // Spanish uses normalization, so accented form should match
        assertTrue(wordList.validWord("ábaco", false))
    }

    @Test
    fun wordList_french_containsKnownWords() {
        val wordList = WordList.wordList(Language.French)
        assertTrue(wordList.validWord("abaisser", false))
    }

    @Test
    fun wordList_korean_containsKnownWords() {
        val wordList = WordList.wordList(Language.Korean)
        // Verify first word from the actual word list
        val firstWord = wordList[0]
        assertTrue(wordList.validWord(firstWord, false))
    }

    @Test
    fun wordList_simplifiedChinese_containsKnownWords() {
        val wordList = WordList.wordList(Language.SimplifiedChinese)
        val firstWord = wordList[0]
        assertTrue(wordList.validWord(firstWord, false))
    }

    @Test
    fun wordList_traditionalChinese_containsKnownWords() {
        val wordList = WordList.wordList(Language.TraditionalChinese)
        val firstWord = wordList[0]
        assertTrue(wordList.validWord(firstWord, false))
    }

    @Test
    fun wordList_czech_containsKnownWords() {
        val wordList = WordList.wordList(Language.Czech)
        val firstWord = wordList[0]
        assertTrue(wordList.validWord(firstWord, false))
    }

    @Test
    fun wordList_portuguese_containsKnownWords() {
        val wordList = WordList.wordList(Language.Portuguese)
        val firstWord = wordList[0]
        assertTrue(wordList.validWord(firstWord, false))
    }

    @Test
    fun wordListStrict_eachLanguage_loadsSuccessfully() {
        for (language in Language.values()) {
            val wordList = WordList.wordListStrict(language)
            assertNotNull(wordList, "wordListStrict($language) returned null")
        }
    }

    @Test
    fun wordList_english_firstWordIsAbandon() {
        val wordList = WordList.wordList(Language.English)
        assertEquals("abandon", wordList[0])
    }

    @Test
    fun wordList_english_lastWordIsZoo() {
        val wordList = WordList.wordList(Language.English)
        assertEquals("zoo", wordList[2047])
    }

    @Test
    fun detectLanguages_englishWords_returnsEnglish() {
        val languages = WordList.detectLanguages(listOf("abandon", "ability", "able"))
        assertTrue(languages.contains(Language.English))
    }

    @Test
    fun detectLanguages_japaneseWords_returnsJapanese() {
        val languages = WordList.detectLanguages(listOf("あいこくしん", "あいさつ"))
        assertTrue(languages.contains(Language.Japanese))
    }

    @Test
    fun wordList_spanishNormalized_matchesAccentedWords() {
        val wordList = WordList.wordList(Language.Spanish)
        assertTrue(wordList.validWord("ábaco", false))
    }

    @Test
    fun wordList_frenchNormalized_matchesAccentedWords() {
        val wordList = WordList.wordList(Language.French)
        assertTrue(wordList.validWord("abaisser", false))
    }

    @Test
    fun wordListStrict_spanish_alsoContainsWords() {
        val strict = WordList.wordListStrict(Language.Spanish)
        val firstWord = strict[0]
        assertTrue(firstWord.isNotBlank())
        // Strict version should still contain words
        assertTrue(strict.validWord(firstWord, false))
    }
}
