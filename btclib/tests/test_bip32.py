#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.bip32` module."

import json
import unittest
from os import path

import pytest

from btclib import bip32, bip39
from btclib.base58 import b58decode, b58encode
from btclib.base58address import p2pkh, p2wpkh_p2sh
from btclib.bech32address import p2wpkh
from btclib.network import NETWORKS


class TestBIP32(unittest.TestCase):
    def test_mainnet(self):
        # bitcoin core derivation style
        rootxprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"

        # m / 0h / 0h / 463h
        addr1 = b"1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5"
        indexes = [0x80000000, 0x80000000, 0x800001CF]
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        assert addr == addr1
        path = "m / 0h / 0h / 463h"
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        assert addr == addr1

        # m / 0h / 0h / 267h
        addr2 = b"11x2mn59Qy43DjisZWQGRResjyQmgthki"
        indexes = [0x80000000, 0x80000000, 0x8000010B]
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        assert addr == addr2
        path = "M / 0H / 0h // 267' / "
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        assert addr == addr2

        # version/key mismatch in extended parent key
        temp = b58decode(rootxprv)
        bad_xprv = b58encode(temp[0:45] + b"\x01" + temp[46:], 78)
        self.assertRaises(ValueError, bip32.derive, bad_xprv, 1)
        # bip32.derive(bad_xprv, 1)

        # version/key mismatch in extended parent key
        xpub = bip32.xpub_from_xprv(rootxprv)
        temp = b58decode(xpub)
        bad_xpub = b58encode(temp[0:45] + b"\x00" + temp[46:], 78)
        self.assertRaises(ValueError, bip32.derive, bad_xpub, 1)
        # bip32.derive(bad_xpub, 1)

        # no private/hardened derivation from pubkey
        self.assertRaises(ValueError, bip32.derive, xpub, 0x80000000)
        # bip32.derive(xpub, 0x80000000)

    def test_testnet(self):
        # bitcoin core derivation style
        rootxprv = "tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK"

        # m / 0h / 0h / 51h
        addr1 = b"mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj"
        indexes = [0x80000000, 0x80000000, 0x80000000 + 51]
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        assert addr == addr1
        path = "m/0h/0h/51h"
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        assert addr == addr1

        # m / 0h / 1h / 150h
        addr2 = b"mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb"
        indexes = [0x80000000, 0x80000000 + 1, 0x80000000 + 150]
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, indexes)))
        assert addr == addr2
        path = "m/0h/1h/150h"
        addr = p2pkh(bip32.xpub_from_xprv(bip32.derive(rootxprv, path)))
        assert addr == addr2

    def test_testnet_versions(self):

        # data cross-checked with Electrum and
        # https://jlopp.github.io/xpub-converter/

        # 128 bits
        raw_entr = bytes.fromhex("6" * 32)
        # 12 words
        mnemonic = bip39.mnemonic_from_entropy(raw_entr, "en")
        rootprv = bip32.mxprv_from_bip39_mnemonic(mnemonic, "", "testnet")

        # p2pkh BIP44
        # m / 44h / coin_type h / account h / change / address_index
        path = "m/44h/1h/0h"
        version = NETWORKS["testnet"]["bip32_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "tpubDChqWo2Xi2wNsxyJBE8ipcTJHLKWcqeeNUKBVTpUCNPZkHzHTm3qKAeHqgCou1t8PAY5ZnJ9QDa6zXSZxmjDnhiBpgZ7f6Yv88wEm5HXVbm"
        assert xpub.decode() == exp
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = p2pkh(xpub_ext)
        exp_address = b"moutHSzeFWViMNEcvBxKzNCMj2kca8MvE1"
        assert address == exp_address
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = p2pkh(xpub_int)
        exp_address = b"myWcXdNais9ExumnGKnNoJwoihQKfNPG9i"
        assert address == exp_address

        # legacy segwit (p2wsh-p2sh)
        # m / 49 h / coin_type h / account h / change / address_index
        path = "m / 49 h/1h/0h"
        version = NETWORKS["testnet"]["slip32_p2wsh_p2sh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "upub5Dj8j7YrwodV68mt58QmNpSzjqjso2WMXEpLGLSvskKccGuXhCh3dTedkzVLAePA617UyXAg2vdswJXTYjU4qjMJaHU79GJVVJCAiy9ezZ2"
        assert xpub.decode() == exp
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = p2wpkh_p2sh(xpub_ext)
        exp_address = b"2Mw8tQ6uT6mHhybarVhjgomUhHQJTeV9A2c"
        assert address == exp_address
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = p2wpkh_p2sh(xpub_int)
        exp_address = b"2N872CRJ3E1CzWjfixXr3aeC3hkF5Cz4kWb"
        assert address == exp_address

        # legacy segwit (p2wsh-p2sh)
        # m / 49 h / coin_type h / account h / change / address_index
        path = "m / 49 h/1h/0h"
        version = NETWORKS["testnet"]["slip32_p2wpkh_p2sh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "Upub5QdDrMHJWmBrWhwG1nskCtnoTdn91PBwqWU1BbiUFXA2ETUSTc5KiaWZZhSoj5c4KUBTr7Anv92P4U9Dqxd1zDTyQkaWYfmVP2U3Js1W5cG"
        assert xpub.decode() == exp

        # native segwit (p2wpkh)
        # m / 84 h / coin_type h / account h / change / address_index
        path = "m / 84 h/1h/0h"
        version = NETWORKS["testnet"]["slip32_p2wpkh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "vpub5ZhJmduYY7M5J2qCJgSW7hunX6zJrr5WuNg2kKt321HseZEYxqJc6Zso47aNXQw3Wf3sA8kppbfsxnLheUNXcL3xhzeBHLNp8fTVBN6DnJF"
        assert xpub.decode() == exp
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        # explicit network is required to discriminate from testnet
        address = p2wpkh(xpub_ext, "regtest")
        exp_address = b"bcrt1qv8lcnmj09rpdqwgl025h2deygur64z4hqf7me5"
        assert address == exp_address
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        # explicit network is required to discriminate from testnet
        address = p2wpkh(xpub_int, "regtest")
        exp_address = b"bcrt1qqhxvky4y6qkwpvdzqjkdafmj20vs5trmt6y8w5"
        assert address == exp_address

        # native segwit (p2wsh)
        # m / 84 h / coin_type h / account h / change / address_index
        path = "m / 84 h/1h/0h"
        version = NETWORKS["testnet"]["slip32_p2wsh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "Vpub5kbPtsdz74uSibzaFLuUwnFbEu2a5Cm7DeKhfb9aPn8HGjoTjEgtBgjirpXr5r9wk87r2ikwhp4P5wxTwhXUkpAdYTkagjqp2PjMmGPBESU"
        assert xpub.decode() == exp

    def test_mainnet_versions(self):

        # data cross-checked with Electrum and
        # https://jlopp.github.io/xpub-converter/

        # 128 bits
        raw_entr = bytes.fromhex("6" * 32)
        # 12 words
        mnemonic = bip39.mnemonic_from_entropy(raw_entr, "en")
        rootprv = bip32.mxprv_from_bip39_mnemonic(mnemonic, "", "testnet")

        # p2pkh BIP44
        # m / 44 h / coin_type h / account h / change / address_index
        path = "m / 44 h / 0 h / 0 h"
        version = NETWORKS["mainnet"]["bip32_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "xpub6C3uWu5Go5q62JzJpbjyCLYRGLYvexFeiepZTsYZ6SRexARkNfjG7GKtQVuGR3KHsyKsAwv7Hz3iNucPp6pfHiLvBczyK1j5CtBtpHB3NKx"
        assert xpub.decode() == exp
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = p2pkh(xpub_ext)
        exp_address = b"1DDKKVHoFWGfctyEEJvrusqq6ipEaieGCq"
        assert address == exp_address
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = p2pkh(xpub_int)
        exp_address = b"1FhKoffreKHzhtBMVW9NSsg3ZF148JPGoR"
        assert address == exp_address

        # legacy segwit (p2wsh-p2sh)
        # m / 49 h / coin_type h / account h / change / address_index
        path = "m / 49 h / 0 h / 0 h"
        version = NETWORKS["mainnet"]["slip32_p2wsh_p2sh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "ypub6YBGdYufCVeoPVmNXfdrWhaBCXsQoLKNetNmD9bPTrKmnKVmiyU8f1uJqwGdmBb8kbAZpHoYfXQTLbWpkXc4skQDAreeCUXdbX9k8vtiHsN"
        assert xpub.decode() == exp
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = p2wpkh_p2sh(xpub_ext)
        exp_address = b"3FmNAiTCWe5kPMgc4dtSgEdY8VuaCiJEH8"
        assert address == exp_address
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = p2wpkh_p2sh(xpub_int)
        exp_address = b"34FLgkoRYX5Q5fqiZCZDwsK5GpXxmFuLJN"
        assert address == exp_address

        # legacy segwit (p2wpkh-p2sh)
        # m / 49 h / coin_type h / account h / change / address_index
        path = "m / 49 h / 0 h / 0 h"
        version = NETWORKS["mainnet"]["slip32_p2wpkh_p2sh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "Ypub6j5Mkne6mTDAp4vkUL6qLmuyvKug1gzxyA2S8QrvqdABQW4gVNrQk8mEeeE7Kcp2z4EYgsofYjnxTm8b3km22EWt1Km3bszdVFRcipc6rXu"
        assert xpub.decode() == exp

        # native segwit (p2wpkh)
        # m / 84 h / coin_type h / account h / change / address_index
        path = "m / 84 h / 0 h / 0 h"
        version = NETWORKS["mainnet"]["slip32_p2wpkh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "zpub6qg3Uc1BAQkQvcBUYMmZHSzbsshSon3FvJ8yvH3ZZMjFNvJkwSji8UUwghiF3wvpvSvcNWVP8kfUhc2V2RwGp6pTC3ouj6njj956f26TniN"
        assert xpub.decode() == exp
        # first addresses
        xpub_ext = bip32.derive(xpub, "./0/0")  # external
        address = p2wpkh(xpub_ext)
        exp_address = b"bc1q0hy024867ednvuhy9en4dggflt5w9unw4ztl5a"
        assert address == exp_address
        xpub_int = bip32.derive(xpub, "./1/0")  # internal
        address = p2wpkh(xpub_int)
        exp_address = b"bc1qy4x03jyl88h2zeg7l287xhv2xrwk4c3ztfpjd2"
        assert address == exp_address

        # native segwit (p2wsh)
        # m / 84 h / coin_type h / account h / change / address_index
        path = "m / 84 h / 0 h / 0 h"
        version = NETWORKS["mainnet"]["slip32_p2wsh_prv"]
        xprv = bip32.derive(rootprv, path, version)
        xpub = bip32.xpub_from_xprv(xprv)
        exp = "Zpub72a8bqjcjNJnMBLrV2EY7XLQbfji28irEZneqYK6w8Zf16sfhr7zDbLsVQficP9j9uzbF6VW1y3ypmeFKf6Dxaw82WvK8WFjcsLyEvMNZjF"
        assert xpub.decode() == exp


def test_exceptions():

    # invalid checksum
    xprv = "xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L"
    with pytest.raises(ValueError, match="not a public or private key: "):
        p2pkh(xprv)

    xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    with pytest.raises(ValueError, match="not a private key: "):
        bip32.xpub_from_xprv(xpub)

    xpub_dict = bip32.deserialize(xpub)
    xpub_dict = bip32.deserialize(xpub_dict)
    xpub_dict["chain_code"] = (xpub_dict["chain_code"])[:-1]
    with pytest.raises(ValueError, match="invalid chain code length: "):
        xpub_dict = bip32.deserialize(xpub_dict)
    xpub_dict = bip32.deserialize(xpub)
    xpub_dict["chain_code"] = "length is 32 but not a chaincode"
    with pytest.raises(ValueError, match="invalid chain code"):
        xpub_dict = bip32.deserialize(xpub_dict)

    version = b"\x04\x88\xAD\xE5"
    seed = "5b56c417303faa3fcba7e57400e120a0"
    with pytest.raises(ValueError, match="unknown private key version: "):
        bip32.rootxprv_from_seed(seed, version)

    with pytest.raises(ValueError, match="too many bits for seed: "):
        bip32.rootxprv_from_seed(seed * 5)

    with pytest.raises(ValueError, match="too few bits for seed: "):
        bip32.rootxprv_from_seed(seed[:-2])


def test_deserialize():
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv_dict = bip32.deserialize(xprv)

    decoded_key = b58decode(xprv, 78)
    assert xprv_dict["version"] == decoded_key[:4]
    assert xprv_dict["depth"] == decoded_key[4]
    assert xprv_dict["parent_fingerprint"] == decoded_key[5:9]
    assert xprv_dict["index"] == decoded_key[9:13]
    assert xprv_dict["chain_code"] == decoded_key[13:45]
    assert xprv_dict["key"] == decoded_key[45:]

    # no harm in deserializing again an already deserialized key
    xprv_dict = bip32.deserialize(xprv_dict)
    xpr2 = bip32.serialize(xprv_dict)
    assert xpr2.decode(), xprv

    xpub = bip32.xpub_from_xprv(xprv)
    xpub2 = bip32.xpub_from_xprv(bip32.deserialize(xprv))
    assert xpub == xpub2


def test_serialize():
    rootxprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
    d = bip32.deserialize(rootxprv)
    assert bip32.serialize(d).decode() == rootxprv

    d["key"] += b"\x00"
    with pytest.raises(ValueError, match="invalid key length: "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["depth"] = 256
    with pytest.raises(ValueError, match="invalid depth "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["parent_fingerprint"] = b"\x00\x00\x00\x01"
    errmsg = "zero depth with non-zero parent fingerprint 0x"
    with pytest.raises(ValueError, match=errmsg):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["index"] = b"\x00\x00\x00\x01"
    with pytest.raises(ValueError, match="zero depth with non-zero index 0x"):
        bip32.serialize(d)

    # FIXME: this failure shoud be required
    # errmsg = "public derivation at depth one level"
    # with pytest.raises(UserWarning, match=errmsg):
    #    bip32.deserialize(bip32.derive(rootxprv, 0))

    xprv = bip32.deserialize(bip32.derive(rootxprv, 0x80000000))
    xprv["parent_fingerprint"] = b"\x00\x00\x00\x00"
    errmsg = "zero parent fingerprint with non-zero depth "
    with pytest.raises(ValueError, match=errmsg):
        bip32.serialize(xprv)

    d = bip32.deserialize(rootxprv)
    d["parent_fingerprint"] += b"\x00"
    with pytest.raises(ValueError, match="invalid parent fingerprint length: "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["index"] += b"\x00"
    with pytest.raises(ValueError, match="invalid index length: "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["chain_code"] += b"\x00"
    with pytest.raises(ValueError, match="invalid chain code length: "):
        bip32.serialize(d)


data_folder = path.join(path.dirname(__file__), "test_data")


def test_bip39_vectors():
    """BIP32 test vectors from BIP39

    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    """
    filename = path.join(data_folder, "bip39_test_vectors.json")
    with open(filename, "r") as f:
        test_vectors = json.load(f)["english"]

    # test_vector[0] and [1], i.e. entropy and mnemonic, are tested in bip39
    for _, _, seed, key in test_vectors:
        assert bip32.rootxprv_from_seed(seed) == key.encode("ascii")


def test_bip32_vectors():
    """BIP32 test vectors

    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """
    filename = path.join(data_folder, "bip32_test_vectors.json")
    with open(filename, "r") as f:
        test_vectors = json.load(f)

    for seed in test_vectors:
        mxprv = bip32.rootxprv_from_seed(seed)
        for der_path, xpub, xprv in test_vectors[seed]:
            assert xprv == bip32.derive(mxprv, der_path).decode()
            assert xpub == bip32.xpub_from_xprv(xprv).decode()


def test_invalid_bip32_xkeys():

    filename = path.join(data_folder, "invalid_bip32_xkeys.json")
    with open(filename, "r") as f:
        test_vectors = json.load(f)

    for xkey, err_msg in test_vectors:
        with pytest.raises(ValueError, match=err_msg):
            bip32.deserialize(xkey)


def test_rootxprv_from_mnemonic():
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    rootxprv = bip32.mxprv_from_bip39_mnemonic(mnemonic, "")
    exp = b"xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1"
    assert rootxprv == exp


def test_derive():
    # root key, zero depth
    rootmxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv = bip32.derive(rootmxprv, b"\x80\x00\x00\x00")
    xprv = bip32.derive(xprv, ".")

    for der_path in ("", "/1"):
        with pytest.raises(ValueError, match="empty derivation path"):
            bip32.derive(xprv, der_path)

    for der_path in (";/0", "invalid index", "800000"):
        with pytest.raises(ValueError, match="invalid derivation path root: "):
            bip32.derive(xprv, der_path)

    with pytest.raises(ValueError, match="derivation path depth greater than 255: "):
        bip32.derive(xprv, "." + 256 * "/0")

    errmsg = "absolute derivation path for non-root master key"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(xprv, "m/44h/0h/1h/0/10")

    with pytest.raises(ValueError, match="index must be 4-bytes, not "):
        bip32.derive(xprv, b"\x00" * 5)

    errmsg = "int too big to convert"
    for index in (256 ** 4, 0x8000000000):
        with pytest.raises(OverflowError, match=errmsg):
            bip32.derive(xprv, index)

    errmsg = "derivation path final depth greater than 255: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(xprv, "." + 255 * "/0")


def test_derive_from_account():

    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    rmxprv = bip32.rootxprv_from_seed(seed)

    path = "m / 44 h / 0 h"
    mxpub = bip32.xpub_from_xprv(bip32.derive(rmxprv, path))

    test_vectors = [
        [0, 0],
        [0, 1],
        [0, 2],
        [1, 0],
        [1, 1],
        [1, 2],
    ]

    for branch, index in test_vectors:
        full_path = path + f"/{branch}/{index}"
        addr = p2pkh(bip32.derive(rmxprv, full_path)).decode()
        assert addr == p2pkh(bip32.derive_from_account(mxpub, branch, index)).decode()

    errmsg = "invalid private derivation at branch level"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive_from_account(mxpub, 0x80000000, 0, True)

    errmsg = "invalid branch: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive_from_account(mxpub, 2, 0)

    errmsg = "invalid private derivation at address index level"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive_from_account(mxpub, 0, 0x80000000)

    path = "m / 44 h / 0"
    mxpub = bip32.xpub_from_xprv(bip32.derive(rmxprv, path))
    errmsg = "public derivation at account level"
    with pytest.raises(UserWarning, match=errmsg):
        bip32.derive_from_account(mxpub, 0, 0)


def test_crack():
    parent_xpub = "xpub6BabMgRo8rKHfpAb8waRM5vj2AneD4kDMsJhm7jpBDHSJvrFAjHJHU5hM43YgsuJVUVHWacAcTsgnyRptfMdMP8b28LYfqGocGdKCFjhQMV"
    child_xprv = "xprv9xkG88dGyiurKbVbPH1kjdYrA8poBBBXa53RKuRGJXyruuoJUDd8e4m6poiz7rV8Z4NoM5AJNcPHN6aj8wRFt5CWvF8VPfQCrDUcLU5tcTm"
    parent_xprv = bip32.crack_prvkey(parent_xpub, child_xprv)
    assert bip32.xpub_from_xprv(parent_xprv).decode() == parent_xpub
    # same check with XKeyDict
    parent_xprv = bip32.crack_prvkey(
        bip32.deserialize(parent_xpub), bip32.deserialize(child_xprv)
    )
    assert bip32.xpub_from_xprv(parent_xprv).decode() == parent_xpub

    errmsg = "extended parent key is not a public key: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.crack_prvkey(parent_xprv, child_xprv)

    errmsg = "extended child key is not a private key: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.crack_prvkey(parent_xpub, parent_xpub)

    child_xpub = bip32.xpub_from_xprv(child_xprv)
    with pytest.raises(ValueError, match="not a parent's child: wrong depths"):
        bip32.crack_prvkey(child_xpub, child_xprv)

    child0_xprv = bip32.derive(parent_xprv, 0)
    grandchild_xprv = bip32.derive(child0_xprv, 0)
    errmsg = "not a parent's child: wrong parent fingerprint"
    with pytest.raises(ValueError, match=errmsg):
        bip32.crack_prvkey(child_xpub, grandchild_xprv)

    hardened_child_xprv = bip32.derive(parent_xprv, 0x80000000)
    with pytest.raises(ValueError, match="hardened child derivation"):
        bip32.crack_prvkey(parent_xpub, hardened_child_xprv)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
