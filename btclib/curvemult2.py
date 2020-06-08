#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve point multiplication functions."""

import heapq
from typing import List, Sequence, Tuple

from .alias import INFJ, Integer, JacPoint, Point
from .curve import Curve, CurveGroup, _jac_from_aff
from .curves import secp256k1
from .utils import int_from_integer


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


def mult(m: int, Q: Point = None, ec: Curve = secp256k1) -> Point:
    """Point multiplication, implemented using 'double and add'.

    Computations use Jacobian coordinates and binary decomposition of m.
    """
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    R = _mult_jac(m, QJ, ec)
    return ec._aff_from_jac(R)


def _double_mult(
    u: int, HJ: JacPoint, v: int, QJ: JacPoint, ec: CurveGroup
) -> JacPoint:

    if u < 0:
        raise ValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise ValueError(f"negative second coefficient: {hex(v)}")

    R = INFJ  # initialize as infinity point
    msb = max(u.bit_length(), v.bit_length())
    while msb > 0:
        if u >> (msb - 1):  # checking msb
            R = ec._add_jac(R, HJ)
            u -= pow(2, u.bit_length() - 1)
        if v >> (msb - 1):  # checking msb
            R = ec._add_jac(R, QJ)
            v -= pow(2, v.bit_length() - 1)
        if msb > 1:
            R = ec._add_jac(R, R)
        msb -= 1

    return R


def double_mult(
    u: Integer, H: Point, v: Integer, Q: Point, ec: Curve = secp256k1
) -> Point:
    """Shamir trick for efficient computation of u*H + v*Q"""

    ec.require_on_curve(H)
    HJ = _jac_from_aff(H)

    ec.require_on_curve(Q)
    QJ = _jac_from_aff(Q)

    u = int_from_integer(u) % ec.n
    v = int_from_integer(v) % ec.n
    R = _double_mult(u, HJ, v, QJ, ec)
    return ec._aff_from_jac(R)


def _multi_mult(
    scalars: Sequence[int], JPoints: Sequence[JacPoint], ec: CurveGroup
) -> JacPoint:
    # source: https://cr.yp.to/badbatch/boscoster2.py

    if len(scalars) != len(JPoints):
        errMsg = "mismatch between number of scalars and points: "
        errMsg += f"{len(scalars)} vs {len(JPoints)}"
        raise ValueError(errMsg)

    # FIXME
    # check for negative scalars
    # x = list(zip([-n for n in scalars], JPoints))
    x: List[Tuple[int, JacPoint]] = []
    for n, PJ in zip(scalars, JPoints):
        if n == 0:
            continue
        x.append((-n, PJ))

    if len(x) == 0:
        return INFJ

    heapq.heapify(x)
    while len(x) > 1:
        np1 = heapq.heappop(x)
        np2 = heapq.heappop(x)
        n1, p1 = -np1[0], np1[1]
        n2, p2 = -np2[0], np2[1]
        p2 = ec._add_jac(p1, p2)
        n1 -= n2
        if n1 > 0:
            heapq.heappush(x, (-n1, p1))
        heapq.heappush(x, (-n2, p2))
    np1 = heapq.heappop(x)
    n1, p1 = -np1[0], np1[1]
    assert n1 < ec.n, "better to take the mod n"
    # n1 %= ec.n
    return _mult_jac(n1, p1, ec)


def multi_mult(
    scalars: Sequence[Integer], Points: Sequence[Point], ec: Curve = secp256k1
) -> Point:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation.
    """

    if len(scalars) != len(Points):
        errMsg = "mismatch between number of scalars and points: "
        errMsg += f"{len(scalars)} vs {len(Points)}"
        raise ValueError(errMsg)

    JPoints: List[JacPoint] = list()
    ints: List[int] = list()
    for P, i in zip(Points, scalars):
        i = int_from_integer(i) % ec.n
        if i == 0:
            continue
        ints.append(i)
        ec.require_on_curve(P)
        JPoints.append(_jac_from_aff(P))

    R = _multi_mult(ints, JPoints, ec)
    return ec._aff_from_jac(R)
