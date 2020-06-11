#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvemult2` module."


import pytest

from btclib.alias import INFJ
from btclib.curvemult2 import _mult_jac, _constant_time_mult_jac
from btclib.tests.test_curves import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_1():
    for x in range(50):
        for ec in low_card_curves.values():
            assert _mult_jac(0, ec.GJ, ec) == INFJ
            assert _mult_jac(0, INFJ, ec) == INFJ

            assert _mult_jac(1, INFJ, ec) == INFJ
            assert _mult_jac(1, ec.GJ, ec) == ec.GJ

            PJ = ec._add_jac(ec.GJ, ec.GJ)
            assert PJ == _mult_jac(2, ec.GJ, ec)

            PJ = _mult_jac(ec.n - 1, ec.GJ, ec)
            assert ec._jac_equality(ec.negate(ec.GJ), PJ)

            assert _mult_jac(ec.n - 1, INFJ, ec) == INFJ
            assert ec._add_jac(PJ, ec.GJ) == INFJ
            assert _mult_jac(ec.n, ec.GJ, ec) == INFJ

            with pytest.raises(ValueError, match="negative m: -0x"):
                _mult_jac(-1, ec.GJ, ec)


def test_2():
    for x in range(50):
        for ec in low_card_curves.values():
            assert _constant_time_mult_jac(0, ec.GJ, ec) == INFJ
            assert _constant_time_mult_jac(0, INFJ, ec) == INFJ

            assert _constant_time_mult_jac(1, INFJ, ec) == INFJ
            assert _constant_time_mult_jac(1, ec.GJ, ec) == ec.GJ

            PJ = ec._add_jac(ec.GJ, ec.GJ)
            assert PJ == _constant_time_mult_jac(2, ec.GJ, ec)

            PJ = _constant_time_mult_jac(ec.n - 1, ec.GJ, ec)
            assert ec._jac_equality(ec.negate(ec.GJ), PJ)

            assert _constant_time_mult_jac(ec.n - 1, INFJ, ec) == INFJ
            assert ec._add_jac(PJ, ec.GJ) == INFJ
            assert _constant_time_mult_jac(ec.n, ec.GJ, ec) == INFJ

            with pytest.raises(ValueError, match="negative m: -0x"):
                _constant_time_mult_jac(-1, ec.GJ, ec)
