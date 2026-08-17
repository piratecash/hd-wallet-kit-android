package io.horizontalsystems.hdwalletkit

import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.digests.RIPEMD160Digest

internal actual object PlatformCrypto {
    actual fun randomBytes(size: Int) = ByteArray(size).also(SecureRandom()::nextBytes)
    actual fun sha256(input: ByteArray) = MessageDigest.getInstance("SHA-256").digest(input)
    actual fun hmacSha512(key: ByteArray, input: ByteArray) = Mac.getInstance("HmacSHA512").run { init(SecretKeySpec(key, algorithm)); doFinal(input) }
    actual fun ripemd160(input: ByteArray) = RIPEMD160Digest().run { update(input, 0, input.size); ByteArray(20).also { doFinal(it, 0) } }
    actual fun normalizeNfkd(input: String) = Normalizer.normalize(input, Normalizer.Form.NFKD)
}
