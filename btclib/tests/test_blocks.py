#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.blocks` module."

import os
import pytest

from btclib.blocks import (
    serialize_block,
    deserialize_block,
    validate_block,
    block_header_hash,
)


# actually second block in chain, first obtainable from other nodes
def test_block_1():

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)
    assert len(block["transactions"]) == 1
    assert serialize_block(block) == block_bytes

    header = block["header"]
    assert header["time"] == 1231469665  # 2009-01-09 03:54:25 GMT+1
    assert (
        header["merkleroot"]
        == "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    assert validate_block(block)
    assert header["bits"] == 0x1D00FFFF
    assert header["nonce"] == 0x9962E301
    assert (
        block_header_hash(header)
        == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    )


# first block with a transaction
def test_block_170():

    fname = "block_170.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)
    assert len(block["transactions"]) == 2
    assert serialize_block(block) == block_bytes

    header = block["header"]
    assert header["time"] == 1231731025  # 2009-01-12 04:30:25 GMT+1
    assert (
        header["merkleroot"]
        == "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
    )
    assert validate_block(block)
    assert header["bits"] == 0x1D00FFFF
    assert header["nonce"] == 0x709E3E28
    assert (
        block_header_hash(header)
        == "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"
    )


def test_block_200000():

    fname = "block_200000.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)
    assert len(block["transactions"]) == 388
    assert serialize_block(block) == block_bytes

    header = block["header"]
    assert header["time"] == 1348310759  # 2012-09-22 12:45:59 GMT+2
    assert (
        header["merkleroot"]
        == "a08f8101f50fd9c9b3e5252aff4c1c1bd668f878fffaf3d0dbddeb029c307e88"
    )
    assert validate_block(block)
    assert header["bits"] == 0x1A05DB8B
    assert header["nonce"] == 0xF7D8D840
    assert (
        block_header_hash(header)
        == "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"
    )


# first block with segwit transaction
# this block has NO witness data (as seen by legacy nodes)
def test_block_481824():

    fname = "block_481824.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)
    assert len(block["transactions"]) == 1866
    assert serialize_block(block) == block_bytes

    header = block["header"]
    assert header["time"] == 1503539857  # 2017-08-24 03:57:37 GMT+2
    assert (
        header["merkleroot"]
        == "6438250cad442b982801ae6994edb8a9ec63c0a0ba117779fbe7ef7f07cad140"
    )
    assert validate_block(block)
    assert header["bits"] == 0x18013CE9
    assert header["nonce"] == 0x2254FF22
    assert (
        block_header_hash(header)
        == "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"
    )

    assert block["transactions"][0]["vin"][0]["txinwitness"] == []


# this block has witness data
def test_block_481824_complete():

    fname = "block_481824_complete.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()

    block = deserialize_block(block_bytes)
    assert len(block["transactions"]) == 1866
    assert serialize_block(block) == block_bytes

    header = block["header"]
    assert header["time"] == 1503539857  # 2017-08-24 03:57:37 GMT+2
    assert (
        header["merkleroot"]
        == "6438250cad442b982801ae6994edb8a9ec63c0a0ba117779fbe7ef7f07cad140"
    )
    assert validate_block(block)
    assert header["bits"] == 0x18013CE9
    assert header["nonce"] == 0x2254FF22
    assert (
        block_header_hash(header)
        == "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"
    )

    assert block["transactions"][0]["vin"][0]["txinwitness"] != []


def test_only_79_bytes():

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    header_bytes = open(filename, "rb").read()
    header_bytes = header_bytes[:79]

    err_msg = "Not enough bytes"
    with pytest.raises(Exception, match=err_msg):
        deserialize_block(header_bytes)

    with pytest.raises(Exception):
        deserialize_block_header(header_bytes)


def test_varint_error():

    fname = "block_1.bin"
    filename = os.path.join(os.path.dirname(__file__), "test_data", fname)
    block_bytes = open(filename, "rb").read()
    block_bytes = block_bytes[:80] + b"\xff"

    err_msg = "Not enough bytes"
    with pytest.raises(Exception, match=err_msg):
        deserialize_block(block_bytes)
