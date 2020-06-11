#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, TypedDict, Union

from . import script, varint
from .alias import Octets, Token
from .utils import bytes_from_octets, Stream


class TxIn(TypedDict):
    txid: str
    vout: int
    scriptSig: List[Token]
    scriptSigHex: str
    sequence: int
    txinwitness: List[str]


def deserialize(stream: Union[Octets, Stream], coinbase: bool = True) -> TxIn:

    if not isinstance(stream, Stream):
        stream = bytes_from_octets(stream)
        stream = Stream(stream)

    txid = stream.read(32)[::-1].hex()
    vout = int.from_bytes(stream.read(4), "little")
    script_length = varint.decode(stream)

    scriptSigHex = stream.read(script_length).hex()
    scriptSig = []
    if not coinbase:
        scriptSig = script.decode(scriptSigHex)

    sequence = int.from_bytes(stream.read(4), "little")
    txinwitness: List[str] = []

    tx_in: TxIn = {
        "txid": txid,
        "vout": vout,
        "scriptSig": scriptSig,
        "scriptSigHex": scriptSigHex,
        "sequence": sequence,
        "txinwitness": txinwitness,
    }

    if coinbase or validate(
        tx_in
    ):  # the block is responsible of validating the coinbase
        return tx_in
    else:
        raise Exception("Invalid transaction input")


def serialize(tx_in: TxIn) -> bytes:
    out = bytes.fromhex(tx_in["txid"])[::-1]
    out += tx_in["vout"].to_bytes(4, "little")
    script_bytes = bytes.fromhex(tx_in["scriptSigHex"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    out += tx_in["sequence"].to_bytes(4, "little")
    return out


def witness_deserialize(stream: Union[Octets, Stream]) -> List[str]:

    if not isinstance(stream, Stream):
        stream = bytes_from_octets(stream)
        stream = Stream(stream)

    witness: List[str] = []
    witness_count = varint.decode(stream)
    for _ in range(witness_count):
        witness_len = varint.decode(stream)
        witness.append(stream.read(witness_len).hex())

    return witness


def witness_serialize(witness: List[str]) -> bytes:

    out = b""

    witness_count = len(witness)
    out += varint.encode(witness_count)
    for i in range(witness_count):
        witness_bytes = bytes.fromhex(witness[i])
        out += varint.encode(len(witness_bytes))
        out += witness_bytes

    return out


def validate(tx_in: TxIn) -> bool:
    return True
