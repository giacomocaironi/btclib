#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass
from typing import List, Type, TypeVar

from . import varint
from .alias import BinaryData
from .utils import bytesio_from_binarydata
from .script import Script

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint:
    hash: str
    n: int

    @classmethod
    def deserialize(cls: Type[_OutPoint], data: BinaryData) -> _OutPoint:
        data = bytesio_from_binarydata(data)
        hash = data.read(32)[::-1].hex()
        n = int.from_bytes(data.read(4), "little")
        return cls(hash, n)

    def serialize(self) -> bytes:
        out = bytes.fromhex(self.hash)[::-1]
        out += self.n.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        null_txid = "00" * 32
        null_vout = 256 ** 4 - 1
        if (self.hash == null_txid) ^ (self.n == null_vout):
            raise ValueError("invalid tx_in")


_TxIn = TypeVar("_TxIn", bound="TxIn")

# TODO: scriptSig for coinbase transactions is now stored as a script with only one value,
# which is the encoded raw script. This simplify the code but makes it  awful to create
# coinbase transactions. One solution might be creating a Script class that as both
# a bytes and a decoded representation


@dataclass
class TxIn:
    prevout: OutPoint
    scriptSig: Script
    nSequence: int
    txinwitness: List[str]

    @classmethod
    def deserialize(cls: Type[_TxIn], data: BinaryData) -> _TxIn:
        stream = bytesio_from_binarydata(data)
        prevout = OutPoint.deserialize(stream)
        scriptSig = Script.deserialize(stream)
        nSequence = int.from_bytes(stream.read(4), "little")
        txinwitness: List[str] = []
        tx_in = cls(
            prevout=prevout,
            scriptSig=scriptSig,
            nSequence=nSequence,
            txinwitness=txinwitness,
        )
        tx_in.assert_valid()
        return tx_in

    def serialize(self) -> bytes:
        out = self.prevout.serialize()
        out += self.scriptSig.serialize()
        out += self.nSequence.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        self.prevout.assert_valid()


def witness_deserialize(data: BinaryData) -> List[str]:
    stream = bytesio_from_binarydata(data)
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
