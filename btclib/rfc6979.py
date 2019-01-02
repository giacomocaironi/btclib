#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Deterministic generation of the nonce following rfc6979

rfc6979 specification:
https://tools.ietf.org/html/rfc6979#section-3.2
code adapted from:
https://github.com/AntonKueltz/fastecdsa/blob/master/fastecdsa/util.py
"""

from struct import pack
import hmac

from btclib.ec import EC, octets, int2octets, octets2int


def bits2int(ec: EC, o: octets) -> int:
    """retain the leftmost bits only"""

    b = octets2int(o)

    """
    i = int.from_bytes(b, 'big')
    # retain the leftmost bits only
    if bytesize > maxbytesize:
        i >>= (bytesize - maxbytesize) * 8
    return i
    """

    """
    maxbytesize = ec.bytesize
    bytesize = len(b)
    # retain the leftmost bytes only
    if bytesize > maxbytesize:
        return int.from_bytes(b[:maxbytesize], 'big')
    else:
        return int.from_bytes(b, 'big')
    """

    h_len = b.bit_length()
    L_n = ec.n.bit_length() # use the L_n leftmost bits of the hash
    n = (h_len - L_n) if h_len >= L_n else 0
    return b >> n


def bits2octets(ec: EC, b: bytes) -> bytes:
    z1 = bits2int(ec, b)
    z2 = z1 % ec.n
    return int2octets(z2, ec.bytesize)


def rfc6979(prv: int, hlb: bytes, ec: EC, hf) -> int:

    if not (0 < prv < ec.n):
        raise ValueError("invalid prv: %s" % prv)

    hlen = hf().digest_size
    v = b'\x01' * hlen
    k = b'\x00' * hlen

    # hlen or qlen ?
    prv_and_m = int2octets(prv, ec.bytesize)
    prv_and_m += bits2octets(ec, hlb)
    k = hmac.new(k, v + b'\x00' + prv_and_m, hf).digest()
    v = hmac.new(k, v, hf).digest()
    k = hmac.new(k, v + b'\x01' + prv_and_m, hf).digest()
    v = hmac.new(k, v, hf).digest()

    qlen = ec.bytesize
    while True:
        t = b''
        while len(t) < qlen:
            v = hmac.new(k, v, hf).digest()
            t = t + v
        nonce = bits2int(ec, t)
        if nonce > 0 and nonce < ec.n:
            # here it should be checked that nonce do not yields a invalid signature
            # but then I should put the signature generation here
            return nonce
        k = hmac.new(k, v + b'\x00', hf).digest()
        v = hmac.new(k, v, hf).digest()
