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
    sequence: int
    txinwitness: List[str]


def deserialize(data: Union[Octets, Stream]) -> TxIn:

    data = bytes_from_octets(data)
    if not isinstance(data, Stream):
        stream = Stream(data)
    else:
        stream = data

    txid = stream.read(32)[::-1].hex()
    vout = int.from_bytes(stream.read(4), "little")
    script_length = varint.decode(stream)
    # data = data[36 + len(varint.encode(script_length)) :]

    if txid != "0" * 64:
        scriptSig = script.decode(stream.read(script_length))
    else:
        scriptSig = stream.read(script_length)

    sequence = int.from_bytes(stream.read(4), "little")
    txinwitness: List[str] = []

    tx_in: TxIn = {
        "txid": txid,
        "vout": vout,
        "scriptSig": scriptSig,
        "sequence": sequence,
        "txinwitness": txinwitness,
    }
    return tx_in


def serialize(tx_in: TxIn) -> bytes:
    out = bytes.fromhex(tx_in["txid"])[::-1]
    out += tx_in["vout"].to_bytes(4, "little")
    if tx_in["txid"] != "0" * 64:
        script_bytes = script.encode(tx_in["scriptSig"])
    else:
        script_bytes = tx_in["scriptSig"]
    out += varint.encode(len(script_bytes))
    out += script_bytes
    out += tx_in["sequence"].to_bytes(4, "little")
    return out


def witness_deserialize(data: Union[Octets, Stream]) -> List[str]:

    data = bytes_from_octets(data)
    if not isinstance(data, Stream):
        stream = Stream(data)
    else:
        stream = data

    witness: List[str] = []

    witness_count = varint.decode(stream)
    # data = data[len(varint.encode(witness_count)) :]
    for _ in range(witness_count):
        witness_len = varint.decode(stream)
        # data = data[len(varint.encode(witness_len)) :]
        witness.append(stream.read(witness_len).hex())
        # data = data[witness_len:]

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
