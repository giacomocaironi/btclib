#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve point multiplication functions."""

# import heapq
# from typing import List, Sequence, Tuple

from .alias import INFJ, JacPoint
from .curve import Curve, CurveGroup
from .curves import secp256k1


def _unsafe_add_jac(Q: JacPoint, R: JacPoint, ec: Curve = secp256k1) -> JacPoint:
    # R and Q must be different

    RZ2 = R[2] * R[2]
    RZ3 = RZ2 * R[2]
    QZ2 = Q[2] * Q[2]
    QZ3 = QZ2 * Q[2]
    if Q[0] * RZ2 % ec.p == R[0] * QZ2 % ec.p:
        if Q[1] * RZ3 % ec.p != R[1] * QZ3 % ec.p:
            return INFJ

    if Q[2] == 0 or R[2] == 0:  # Infinity point in Jacobian coordinates
        return R

    T = (Q[1] * RZ3) % ec.p
    U = (R[1] * QZ3) % ec.p
    W = (U - T) % ec.p

    M = (Q[0] * RZ2) % ec.p
    N = (R[0] * QZ2) % ec.p
    V = (N - M) % ec.p

    V2 = V * V
    V3 = V2 * V
    MV2 = M * V2
    X = (W * W - V3 - 2 * MV2) % ec.p
    Y = (W * (MV2 - X) - T * V3) % ec.p
    Z = (V * Q[2] * R[2]) % ec.p
    return X, Y, Z


def _double_jac(Q: JacPoint, ec: Curve = secp256k1) -> JacPoint:

    if Q[2] == 0:
        return INFJ

    QZ2 = Q[2] * Q[2]
    QY2 = Q[1] * Q[1]
    W = (3 * Q[0] * Q[0] + ec._a * QZ2 * QZ2) % ec.p
    V = (4 * Q[0] * QY2) % ec.p
    X = (W * W - 2 * V) % ec.p
    Y = (W * (V - X) - 8 * QY2 * QY2) % ec.p
    Z = (2 * Q[1] * Q[2]) % ec.p
    return X, Y, Z


def _mult_jac(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication of a curve point in Jacobian coordinates.

    This implementation uses 'double & add' algorithm,
    binary decomposition of m,
    jacobian coordinates.
    It is not constant-time.

    The input point is assumed to be on curve,
    m is assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # there is not a compelling reason to optimize for INFJ, even if possible
    # if Q[2] == 1:  # Infinity point, Jacobian coordinates
    #     return INFJ  # return Infinity point
    R = INFJ  # initialize as infinity point
    while m > 0:  # use binary representation of m
        if m & 1:  # if least significant bit is 1
            R = _unsafe_add_jac(R, Q, ec)  # then add current Q
        m = m >> 1  # remove the bit just accounted for
        Q = _double_jac(Q, ec)  # double Q for next step
    return R


def _constant_time_mult_jac(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication of a curve point in Jacobian coordinates.

    This implementation uses 'montgomery ladder' algorithm,
    jacobian coordinates.
    It is constant-time if the binary size of Q remains the same.

    The input point is assumed to be on curve,
    m is assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    if Q == INFJ:
        return Q

    R = INFJ  # initialize as infinity point
    for m in [int(i) for i in bin(m)[2:]]:  # goes through binary digits
        if m == 0:
            Q = ec._add_jac(R, Q)
            R = _double_jac(R, ec)
        else:
            R = ec._add_jac(R, Q)
            Q = _double_jac(Q, ec)
    return R
