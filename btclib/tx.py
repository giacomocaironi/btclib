#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Bitcoin Transaction.

https://en.bitcoin.it/wiki/Transaction
https://learnmeabitcoin.com/guide/coinbase-transaction
https://bitcoin.stackexchange.com/questions/20721/what-is-the-format-of-the-coinbase-transaction
"""

from typing import List, TypedDict, Union

from . import tx_in, tx_out, varint
from .alias import Octets
from .tx_in import TxIn
from .tx_out import TxOut
from .utils import bytes_from_octets, hash256, Stream


class Tx(TypedDict):
    version: int
    locktime: int
    vin: List[TxIn]
    vout: List[TxOut]
    witness_flag: bool


def deserialize(stream: Union[Octets, Stream]) -> Tx:

    if not isinstance(stream, Stream):
        stream = bytes_from_octets(stream)
        stream = Stream(stream)

    version = int.from_bytes(stream.read(4), "little")

    witness_flag = False
    if stream.data[:2] == b"\x00\x01":
        witness_flag = True
        stream.read(2)

    input_count = varint.decode(stream)
    vin: List[TxIn] = []
    for _ in range(input_count):
        tx_input = tx_in.deserialize(stream)
        vin.append(tx_input)

    output_count = varint.decode(stream)
    vout: List[TxOut] = []
    for _ in range(output_count):
        tx_output = tx_out.deserialize(stream)
        vout.append(tx_output)

    if witness_flag:
        for tx_input in vin:
            witness = tx_in.witness_deserialize(stream)
            tx_input["txinwitness"] = witness

    locktime = int.from_bytes(stream.read(4), "little")

    tx: Tx = {
        "version": version,
        "locktime": locktime,
        "vin": vin,
        "vout": vout,
        "witness_flag": witness_flag,
    }
    return tx


def serialize(tx: Tx, include_witness: bool = True) -> bytes:
    out = tx["version"].to_bytes(4, "little")
    if tx["witness_flag"] and include_witness:
        out += b"\x00\x01"

    out += varint.encode(len(tx["vin"]))
    for tx_input in tx["vin"]:
        out += tx_in.serialize(tx_input)

    out += varint.encode(len(tx["vout"]))
    for tx_output in tx["vout"]:
        out += tx_out.serialize(tx_output)

    if tx["witness_flag"] and include_witness:
        for tx_input in tx["vin"]:
            out += tx_in.witness_serialize(tx_input["txinwitness"])

    out += tx["locktime"].to_bytes(4, "little")
    return out


def txid(tx: Tx) -> str:
    return hash256(serialize(tx, False))[::-1].hex()


def hash_value(tx: Tx) -> str:
    return hash256(serialize(tx))[::-1].hex()
