#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.sighash` module."

# test vector at https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
from btclib import script, dsa, der
from btclib.tx_in import TxIn, OutPoint
from btclib.tx_out import TxOut
from btclib.tx import Tx
from btclib.sighash import _get_witness_v0_scriptCodes, get_sighash, segwit_v0_sighash
from btclib.curvemult import mult
from btclib.secpoint import bytes_from_point

# block 170
def test_first_transaction():
    transaction = Tx.deserialize(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    )
    previous_txout = TxOut(
        nValue=5000000000,
        scriptPubKey=script.decode(
            "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
        ),
    )
    sighash = get_sighash(transaction, previous_txout, 0, 0x01)
    assert (
        sighash.hex()
        == "7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19"
    )
    pubkey = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
    signature = "304402204E45E16932B8AF514961A1D3A1A25FDF3F4F7732E9D624C6C61548AB5FB8CD410220181522EC8ECA07DE4860A4ACDD12909D831CC56CBBAC4622082221A8768D1D0901"
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


# 8fea2a92db2940ebce62610b162bfe0ca13229e08cb384a886a6f677e2812e52
def test_legacy_p2pkh():
    pubkey = "04280c8f66bf2ccaeb3f60a19ad4a06365f8bd6178aab0e709df2173df8f553366549aec336aae8742a84702b6c7c3052d89f5d76d535ec3716e72187956351613"
    signature = "3045022100ea43c4800d1a860ec89b5273898a146cfb01d34ff4c364d24a110c480d0e3f7502201c82735577f932f1ca8e1c54bf653e0f8e74e408fe83666bc85cac4472ec950801"
    scriptSig = [signature, pubkey]
    previous_txout = TxOut(
        1051173696,
        [
            "OP_DUP",
            "OP_HASH160",
            "82ac30f58baf99ec9d14e6181eee076f4e27f69c",
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ],
    )
    tx = Tx(
        1,
        0,
        vin=[
            TxIn(
                OutPoint(
                    "d8343a35ba951684f2969eafe833d9e6fe436557b9707ae76802875952e860fc",
                    1,
                ),
                scriptSig,
                0xFFFFFFFF,
                [],
            )
        ],
        vout=[
            TxOut(
                2017682,
                script.decode("76a91413bd20236d0da56492c325dce289b4da35b4b5bd88ac"),
            ),
            TxOut(
                1049154982,
                script.decode("76a914da169b45781ca210f8c11617ba66bd843da76b1688ac"),
            ),
        ],
    )
    sighash = get_sighash(tx, previous_txout, 0, 0x01)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


# the following tests are taken from python-bitcoinlib tests
def test_p2pk():
    pubkey = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    signature = "304402200A5C6163F07B8D3B013C4D1D6DBA25E780B39658D79BA37AF7057A3B7F15FFA102201FD9B4EAA9943F734928B99A83592C2E7BF342EA2680F6A2BB705167966B742001"
    scriptPubKey = [pubkey, "OP_CHECKSIG"]
    scriptSig = [signature]
    founding_tx = Tx(
        1,
        0,
        vin=[
            TxIn(
                OutPoint("00" * 32, 0xFFFFFFFF), [script.encode([0, 0])], 0xFFFFFFFF, []
            )
        ],
        vout=[TxOut(0, scriptPubKey)],
    )
    recieving_tx = Tx(
        1,
        0,
        vin=[
            TxIn(
                OutPoint(founding_tx.txid, 0),
                [script.encode(scriptSig)],
                0xFFFFFFFF,
                [],
            )
        ],
        vout=[TxOut(0, [])],
    )
    sighash = get_sighash(recieving_tx, founding_tx.vout[0], 0, 0x01)

    assert dsa._verify(
        sighash,
        bytes_from_point(mult(10)).hex(),
        der._serialize(*dsa._sign(sighash, 10)).hex(),
    )

    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])


def test_p2pkh():
    pubkey = "038282263212C609D9EA2A6E3E172DE238D8C39CABD5AC1CA10646E23FD5F51508"
    signature = "304402206E05A6FE23C59196FFE176C9DDC31E73A9885638F9D1328D47C0C703863B8876022076FEB53811AA5B04E0E79F938EB19906CC5E67548BC555A8E8B8B0FC603D840C01"
    scriptPubKey = [
        "OP_DUP",
        "OP_HASH160",
        "1018853670F9F3B0582C5B9EE8CE93764AC32B93",
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]
    scriptSig = [signature, pubkey]
    founding_tx = Tx(
        1,
        0,
        vin=[
            TxIn(
                OutPoint("00" * 32, 0xFFFFFFFF), [script.encode([0, 0])], 0xFFFFFFFF, []
            )
        ],
        vout=[TxOut(0, scriptPubKey)],
    )
    recieving_tx = Tx(
        1,
        0,
        vin=[
            TxIn(
                OutPoint(founding_tx.txid, 0),
                [script.encode(scriptSig)],
                0xFFFFFFFF,
                [],
            )
        ],
        vout=[TxOut(0, [])],
    )
    sighash = get_sighash(recieving_tx, founding_tx.vout[0], 0, 0x01)
    assert dsa._verify(sighash, bytes.fromhex(pubkey), bytes.fromhex(signature)[:-1])
