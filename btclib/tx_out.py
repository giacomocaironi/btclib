#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass
from typing import Type, TypeVar

from . import varint
from .script import Script
from .alias import BinaryData
from .utils import bytesio_from_binarydata

_TxOut = TypeVar("_TxOut", bound="TxOut")


@dataclass
class TxOut:
    nValue: int  # satoshis
    scriptPubKey: Script

    @classmethod
    def deserialize(cls: Type[_TxOut], data: BinaryData) -> _TxOut:
        stream = bytesio_from_binarydata(data)
        nValue = int.from_bytes(stream.read(8), "little")
        script_length = varint.decode(stream)
        scriptPubKey = Script(stream.read(script_length))
        tx_out = cls(nValue=nValue, scriptPubKey=scriptPubKey)
        tx_out.assert_valid()
        return tx_out

    def serialize(self) -> bytes:
        out = self.nValue.to_bytes(8, "little")
        out += self.scriptPubKey.serialize()
        return out

    def assert_valid(self) -> None:
        if self.nValue < 0:
            raise ValueError(f"negative value: {self.nValue}")
        if self.nValue > 2099999997690000:
            raise ValueError(f"value too high: {self.nValue}")
