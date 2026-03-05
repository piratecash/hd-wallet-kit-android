package io.horizontalsystems.hdwalletkit

import io.horizontalsystems.hdwalletkit.HDWallet.Purpose
import java.lang.IllegalStateException
import java.math.BigInteger

enum class HDExtendedKeyVersion(
    val value: Int,
    val base58Prefix: String
) {

    // bip44
    xprv(0x0488ade4, "xprv"),
    xpub(0x0488b21e, "xpub"),

    // bip49
    yprv(0x049d7878, "yprv"),
    ypub(0x049d7cb2, "ypub"),

    // bip84
    zprv(0x04b2430c, "zprv"),
    zpub(0x04b24746, "zpub"),

    // litecoin bip44
    Ltpv(0x019d9cfe, "Ltpv"),
    Ltub(0x019da462, "Ltub"),

    // litecoin bip49
    Mtpv(0x01b26792, "Mtpv"),
    Mtub(0x01b26ef6, "Mtub"),

    // dogecoin bip44
    dgpv(0x02fac398, "dgpv"),
    dgub(0x02facafd, "dgub"),

    // dash bip44
    drkv(0x02fe52cc, "drkv"),
    drkp(0x02fe52f8, "drkp");

    val coinTypes: List<ExtendedKeyCoinType>
        get() = when (this) {
            xprv, xpub, zprv, zpub -> {
                listOf(ExtendedKeyCoinType.Bitcoin, ExtendedKeyCoinType.Litecoin)
            }

            yprv, ypub -> {
                listOf(ExtendedKeyCoinType.Bitcoin)
            }

            Ltpv, Ltub, Mtpv, Mtub -> {
                listOf(ExtendedKeyCoinType.Litecoin)
            }

            dgpv, dgub -> {
                listOf(ExtendedKeyCoinType.Dogecoin)
            }

            drkv, drkp -> {
                listOf(ExtendedKeyCoinType.Dash)
            }
        }

    val purposes: List<Purpose>
        get() = when (this) {
            xprv, xpub -> {
                listOf(Purpose.BIP44, Purpose.BIP86)
            }

            Ltpv, Ltub, dgpv, dgub, drkv, drkp -> {
                listOf(Purpose.BIP44)
            }

            yprv, ypub, Mtpv, Mtub -> {
                listOf(Purpose.BIP49)
            }

            zprv, zpub -> {
                listOf(Purpose.BIP84)
            }
        }

    val pubKey: HDExtendedKeyVersion
        get() = when (this) {
            xprv -> xpub
            yprv -> ypub
            zprv -> zpub
            Ltpv -> Ltub
            Mtpv -> Mtub
            dgpv -> dgub
            drkv -> drkp
            xpub, ypub, zpub, Ltub, Mtub, dgub, drkp -> this
        }

    val privKey: HDExtendedKeyVersion
        get() = when (this) {
            xprv, yprv, zprv, Ltpv, Mtpv, dgpv, drkv -> this
            xpub, ypub, zpub, Ltub, Mtub, dgub, drkp -> throw IllegalStateException("No privateKey of $base58Prefix")
        }

    val isPublic: Boolean
        get() = when (this) {
            xprv, yprv, zprv, Ltpv, Mtpv, dgpv, drkv -> false
            xpub, ypub, zpub, Ltub, Mtub, dgub, drkp -> true
        }

    companion object {
        fun initFrom(
            purpose: Purpose,
            coinType: ExtendedKeyCoinType,
            isPrivate: Boolean
        ): HDExtendedKeyVersion {
            return when (purpose) {
                Purpose.BIP44 -> {
                    when (coinType) {
                        ExtendedKeyCoinType.Bitcoin -> if (isPrivate) xprv else xpub
                        ExtendedKeyCoinType.Litecoin -> if (isPrivate) Ltpv else Ltub
                        ExtendedKeyCoinType.Dogecoin -> if (isPrivate) dgpv else dgub
                        ExtendedKeyCoinType.Dash -> if (isPrivate) drkv else drkp
                    }
                }

                Purpose.BIP49 -> {
                    when (coinType) {
                        ExtendedKeyCoinType.Bitcoin -> if (isPrivate) yprv else ypub
                        ExtendedKeyCoinType.Litecoin -> if (isPrivate) Mtpv else Mtub
                        ExtendedKeyCoinType.Dogecoin,
                        ExtendedKeyCoinType.Dash -> throw IllegalStateException("BIP49 not supported for $coinType")
                    }
                }

                Purpose.BIP84 -> {
                    if (isPrivate) zprv else zpub
                }

                Purpose.BIP86 -> {
                    if (isPrivate) xprv else xpub
                }
            }
        }

        fun initFrom(prefix: String): HDExtendedKeyVersion? =
            values().firstOrNull { it.base58Prefix == prefix }

        fun initFrom(version: ByteArray): HDExtendedKeyVersion? =
            values().firstOrNull { it.value == BigInteger(version).toInt() }
    }
}

enum class ExtendedKeyCoinType {
    Bitcoin, Litecoin, Dogecoin, Dash
}
