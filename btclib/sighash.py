#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, Union
from copy import deepcopy

from . import script, tx, tx_out, varint
from .alias import Octets, Script, Token
from .scriptpubkey import payload_from_scriptPubKey
from .utils import bytes_from_octets, hash256, sha256
from .hashes import tagged_hash
from .script import encode as script_encode

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


# workaround to handle CTransactions
def _get_bytes(a: Union[int, str]) -> bytes:
    return int.to_bytes(a, 32, "big") if isinstance(a, int) else bytes.fromhex(a)


def legacy_sighash(
    scriptCode: Octets, transaction: tx.Tx, input_index: int, hashtype: int
) -> bytes:
    new_tx = deepcopy(transaction)
    for txin in new_tx.vin:
        txin.scriptSig = []
    # TODO: delete sig from scriptCode (even if non standard)
    new_tx.vin[input_index].scriptSig = script.decode(scriptCode)
    if hashtype & 31 == 0x02:
        new_tx.vout = []
        for i, txin in enumerate(new_tx.vin):
            if i != input_index:
                txin.nSequence = 0

    if hashtype & 31 == 0x03:
        # sighash single bug
        if input_index >= len(new_tx.vout):
            return (256 ** 31).to_bytes(32, "big")
        new_tx.vout = new_tx.vout[: input_index + 1]
        for txout in new_tx.vout[:-1]:
            txout.scriptPubKey = []
            txout.nValue = 256 ** 8 - 1
        for i, txin in enumerate(new_tx.vin):
            if i != input_index:
                txin.nSequence = 0

    if hashtype & 0x80:
        new_tx.vin = [new_tx.vin[input_index]]

    preimage = new_tx.serialize()
    preimage += hashtype.to_bytes(4, "little")

    return hash256(preimage)


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def segwit_v0_sighash(
    scriptCode: Octets, transaction: tx.Tx, input_index: int, hashtype: int, amount: int
) -> bytes:

    hashtype_hex: str = hashtype.to_bytes(4, "little").hex()
    if hashtype_hex[0] != "8":
        hashPrevouts = b""
        for vin in transaction.vin:
            hashPrevouts += _get_bytes(vin.prevout.hash)[::-1]
            hashPrevouts += vin.prevout.n.to_bytes(4, "little")
        hashPrevouts = hash256(hashPrevouts)
    else:
        hashPrevouts = b"\x00" * 32

    if hashtype_hex[1] == "1" and hashtype_hex[0] != "8":
        hashSequence = b""
        for vin in transaction.vin:
            hashSequence += vin.nSequence.to_bytes(4, "little")
        hashSequence = hash256(hashSequence)
    else:
        hashSequence = b"\x00" * 32

    if hashtype_hex[1] != "2" and hashtype_hex[1] != "3":
        hashOutputs = b""
        for vout in transaction.vout:
            hashOutputs += vout.serialize()
        hashOutputs = hash256(hashOutputs)
    elif hashtype_hex[1] == "3" and input_index < len(transaction.vout):
        hashOutputs = hash256(transaction.vout[input_index].serialize())
    else:
        hashOutputs = b"\x00" * 32

    scriptCode = bytes_from_octets(scriptCode)

    outpoint = _get_bytes(transaction.vin[input_index].prevout.hash)[::-1]
    outpoint += transaction.vin[input_index].prevout.n.to_bytes(4, "little")

    preimage = transaction.nVersion.to_bytes(4, "little")
    preimage += hashPrevouts
    preimage += hashSequence
    preimage += outpoint
    preimage += varint.encode(len(scriptCode)) + scriptCode
    preimage += amount.to_bytes(8, "little")  # value
    preimage += transaction.vin[input_index].nSequence.to_bytes(4, "little")
    preimage += hashOutputs
    preimage += transaction.nLockTime.to_bytes(4, "little")
    preimage += bytes.fromhex(hashtype_hex)

    return hash256(preimage)


def segwit_v1_sighash(
    transaction: tx.Tx,
    input_index: int,
    amounts: List[int],
    scriptpubkeys: List[List[Token]],
    hashtype: int,
    ext_flag: int,
    annex: bytes,
) -> bytes:

    preimage = b"\x00"
    preimage += hashtype.to_bytes(4, "big")
    preimage += transaction.nVersion.to_bytes(4, "little")
    preimage += transaction.nLockTime.to_bytes(4, "little")

    if hashtype & 0x80 != SIGHASH_ANYONECANPAY:
        sha_prevouts = b""
        sha_amounts = b""
        sha_scriptpubkeys = b""
        sha_sequences = b""
        for i, vin in enumerate(transaction.vin):
            sha_prevouts += _get_bytes(vin.prevout.hash)[::-1]
            sha_prevouts += vin.prevout.n.to_bytes(4, "little")
            sha_amounts += amounts[i].to_bytes(8, "little")
            sha_scriptpubkeys += script_encode(scriptpubkeys[i])
            sha_sequences += vin.nSequence.to_bytes(4, "little")
        preimage += sha256(sha_prevouts)
        preimage += sha256(sha_amounts)
        preimage += sha256(sha_scriptpubkeys)
        preimage += sha256(sha_sequences)

    if hashtype & 0x03 not in [SIGHASH_NONE, SIGHASH_SINGLE]:
        sha_outputs = b""
        for vout in transaction.vout:
            sha_outputs += vout.serialize()
        preimage += sha256(sha_outputs)

    annex_present = int(bool(annex))
    preimage += (2 * ext_flag + annex_present).to_bytes(1, "little")

    if hashtype & 0x80 == SIGHASH_ANYONECANPAY:
        preimage += transaction.vin[input_index].prevout.serialize()
        preimage += amounts[input_index].to_bytes(8, "little")
        preimage += script_encode(scriptpubkeys[input_index])
        preimage += transaction.vin[input_index].nSequence.to_bytes(4, "little")
    else:
        preimage += input_index.to_bytes(4, "little")

    if annex_present:
        sha_annex = varint.encode(len(annex)) + annex
        preimage += sha256(sha_annex)

    if hashtype & 0x03 == SIGHASH_SINGLE:
        preimage += sha256(transaction.vout[input_index].serialize())

    sig_hash = tagged_hash("TapSighash", preimage)
    return sig_hash


# FIXME: remove OP_CODESEPARATOR only if exectued
def _get_legacy_scriptCodes(scriptPubKey: Script) -> List[str]:
    scriptCodes: List[str] = []
    current_script: List[Token] = []
    for token in scriptPubKey[::-1]:
        if token == "OP_CODESEPARATOR":
            scriptCodes.append(script.encode(current_script[::-1]).hex())
        else:
            current_script.append(token)
    scriptCodes.append(script.encode(current_script[::-1]).hex())
    scriptCodes = scriptCodes[::-1]
    return scriptCodes


# FIXME: remove OP_CODESEPARATOR only if executed
def _get_witness_v0_scriptCodes(scriptPubKey: Script) -> List[str]:
    scriptCodes: List[str] = []
    try:
        script_type = payload_from_scriptPubKey(scriptPubKey)[0]
    except ValueError:
        script_type = "unknown"
    if script_type == "p2wpkh":  # simple p2wpkh
        pubkeyhash = scriptPubKey[1]
        assert isinstance(pubkeyhash, str)
        scriptCodes.append(f"76a914{pubkeyhash}88ac")
    else:
        current_script: List[Token] = []
        for token in scriptPubKey[::-1]:
            if token == "OP_CODESEPARATOR":
                scriptCodes.append(script.encode(current_script[::-1]).hex())
            current_script.append(token)
        scriptCodes.append(script.encode(current_script[::-1]).hex())
        scriptCodes = scriptCodes[::-1]
    return scriptCodes


def get_sighash(
    transaction: tx.Tx,
    previous_output: tx_out.TxOut,
    input_index: int,
    sighash_type: int,
) -> bytes:

    value = previous_output.nValue

    scriptPubKey = previous_output.scriptPubKey
    try:
        script_type = payload_from_scriptPubKey(scriptPubKey)[0]
        if script_type == "p2sh":
            scriptPubKey = transaction.vin[input_index].scriptSig
    except:
        pass

    if len(scriptPubKey) == 2 and scriptPubKey[0] == 0:  # is segwit
        script_type = payload_from_scriptPubKey(scriptPubKey)[0]
        if script_type == "p2wpkh":
            scriptCode = _get_witness_v0_scriptCodes(scriptPubKey)[0]
        elif script_type == "p2wsh":
            # the real script is contained in the witness
            scriptCode = _get_witness_v0_scriptCodes(
                script.decode(transaction.vin[input_index].txinwitness[-1])
            )[0]
        return segwit_v0_sighash(
            bytes.fromhex(scriptCode), transaction, input_index, sighash_type, value
        )
    else:
        scriptCode = _get_legacy_scriptCodes(scriptPubKey)[0]
        return legacy_sighash(scriptCode, transaction, input_index, sighash_type)


# def sign(
#     transaction: tx.Tx,
#     previous_output: tx.TxOut,
#     input_index: int,
#     prvkey: int,
#     sighash_type: int,
# ) -> str:
#     sighash = get_sighash(transaction, previous_output, input_index, sighash_type)
#     signature = dsa.serialize(*dsa._sign(sighash, prvkey))
#     signature += sighash_type.to_bytes(1, "little")
#     return signature.hex()
