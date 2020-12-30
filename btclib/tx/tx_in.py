#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import InitVar, dataclass, field
from typing import Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from btclib import var_bytes
from btclib.alias import BinaryData
from btclib.exceptions import BTClibValueError
from btclib.tx.out_point import OutPoint
from btclib.tx.witness import Witness
from btclib.utils import bytesio_from_binarydata

_TxIn = TypeVar("_TxIn", bound="TxIn")

TX_IN_COMPARES_WITNESS = True


@dataclass
class TxIn(DataClassJsonMixin):
    prev_out: OutPoint = OutPoint()
    # TODO make it { "asm": "", "hex": "" }
    script_sig: bytes = field(
        default=b"",
        metadata=config(
            field_name="scriptSig", encoder=lambda v: v.hex(), decoder=bytes.fromhex
        ),
    )
    # If all TxIns have final (0xffffffff) sequence numbers
    # then Tx lock_time is irrelevant.
    #
    # Set to 0xFFFFFFFE to enables nLocktime (e.g. to discourage fee sniping)
    # and disables Replace-By-Fee (RBF).
    #
    # RBF txs typically have the sequence of each input set to 0xFFFFFFFD.
    #
    # Because sequence locks require that the sequence field be set
    # lower than 0xFFFFFFFD to be meaningful,
    # all sequence locked transactions are opting into RBF.
    sequence: int = 0
    script_witness: Witness = field(
        default=Witness(),
        init=True,  # must be True, probably a bug of dataclasses_json
        repr=True,
        compare=TX_IN_COMPARES_WITNESS,
        metadata=config(field_name="txinwitness"),
    )
    check_validity: InitVar[bool] = True

    @property
    def outpoint(self) -> OutPoint:
        "Return the outpoint OutPoint for compatibility with CTxIn."
        return self.prev_out

    @property
    def scriptSig(self) -> bytes:  # pylint: disable=invalid-name
        "Return the scriptSig bytes for compatibility with CTxIn."
        return self.script_sig

    @property
    def nSequence(self) -> int:  # pylint: disable=invalid-name
        "Return the nSequence int for compatibility with CTxIn."
        return self.sequence

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def is_segwit(self) -> bool:
        # self.prev_out has no segwit information
        return self.script_witness.stack != []

    def is_coinbase(self) -> bool:
        return self.prev_out.is_coinbase()

    def assert_valid(self) -> None:
        self.prev_out.assert_valid()

        # TODO check script_sig

        # must be a 4-bytes int
        if not 0 <= self.sequence <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid sequence: {self.sequence}")

        if self.script_witness:
            self.script_witness.assert_valid()

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        out = self.prev_out.serialize()
        out += var_bytes.serialize(self.script_sig)
        out += self.sequence.to_bytes(4, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(cls: Type[_TxIn], data: BinaryData, check_validity: bool = True) -> _TxIn:

        s = bytesio_from_binarydata(data)
        prev_out = OutPoint.parse(s)
        script_sig = var_bytes.parse(s)
        sequence = int.from_bytes(s.read(4), byteorder="little", signed=False)

        return cls(prev_out, script_sig, sequence, Witness(), check_validity)