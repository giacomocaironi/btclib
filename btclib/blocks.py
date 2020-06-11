#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict, List, Union
from hashlib import sha256

from . import varint, tx
from .utils import hash256, Stream, bytes_from_octets
from .alias import Octets


class BlockHeader(TypedDict):
    version: int
    previousblockhash: str
    merkleroot: str
    time: int
    bits: int
    nonce: int
    hash: str


def deserialize_block_header(stream: Union[Octets, Stream]) -> BlockHeader:

    if not isinstance(stream, Stream):
        stream = bytes_from_octets(stream)
        stream = Stream(stream)

    version = int.from_bytes(stream.read(4), "little")
    previousblockhash = stream.read(32)[::-1].hex()
    merkleroot = stream.read(32)[::-1].hex()
    timestamp = int.from_bytes(stream.read(4), "little")
    bits = int.from_bytes(stream.read(4), "little")
    nonce = int.from_bytes(stream.read(4), "little")

    header: BlockHeader = {
        "version": version,
        "previousblockhash": previousblockhash,
        "merkleroot": merkleroot,
        "time": timestamp,
        "bits": bits,
        "nonce": nonce,
        "hash": "",
    }

    header["hash"] = hash256(serialize_block_header(header))[::-1].hex()

    return header


def serialize_block_header(header: BlockHeader) -> bytes:
    out = header["version"].to_bytes(4, "little")
    out += bytes.fromhex(header["previousblockhash"])[::-1]
    out += bytes.fromhex(header["merkleroot"])[::-1]
    out += header["time"].to_bytes(4, "little")
    out += header["bits"].to_bytes(4, "little")
    out += header["nonce"].to_bytes(4, "little")
    return out


class Block(TypedDict):
    header: BlockHeader
    transactions: List[tx.Tx]


def generate_merkle_root(transactions: List[tx.Tx]) -> str:
    hashes = [bytes.fromhex(tx.txid(transaction))[::-1] for transaction in transactions]
    hashes_buffer = []
    while len(hashes) != 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        for x in range(len(hashes) // 2):
            hashes_buffer.append(
                sha256(sha256(hashes[2 * x] + hashes[2 * x + 1]).digest()).digest()
            )
        hashes = hashes_buffer[:]
        hashes_buffer = []
    return hashes[0][::-1].hex()


def deserialize_block(stream: Union[Octets, Stream]) -> Block:

    if not isinstance(stream, Stream):
        stream = bytes_from_octets(stream)
        stream = Stream(stream)

    header = deserialize_block_header(stream)

    transaction_count = varint.decode(stream)
    transactions: List[tx.Tx] = []
    for x in range(transaction_count):
        transaction = tx.deserialize(stream)
        transactions.append(transaction)

    block: Block = {"header": header, "transactions": transactions}

    return block


def serialize_block(block: Block) -> bytes:
    out = serialize_block_header(block["header"])
    out += varint.encode(len(block["transactions"]))
    for transaction in block["transactions"]:
        out += tx.serialize(transaction)
    return out
