#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import time
import random
from hashlib import sha256
import struct
from btclib import varint


# does not add network_string
def add_headers(name: str, payload: bytes):
    command = name + ((12 - len(name)) * "\00")
    payload_len = struct.pack("I", len(payload))
    checksum = sha256(sha256(payload).digest()).digest()[:4]
    return command.encode() + payload_len + checksum + payload


def verify_headers(message: bytes):
    # message_name = message[4:16]
    payload_len = int.from_bytes(message[16:20], "little")
    checksum = message[20:24]
    payload = message[24:]
    if len(payload) != payload_len:
        raise Exception("Wrong payload length")
    if checksum != sha256(sha256(payload).digest()).digest()[:4]:
        raise Exception("Wrong checksum, the message might have been tampered")

    return True


def get_payload(message: bytes):
    try:
        verify_headers(message)
    except Exception:
        raise Exception("Incorrect headers")
    message_name = message[4:16].rstrip(b"\x00")
    payload = message[24:]

    return [message_name, payload]


class NetworkMessage:
    def __init__(self, name, raw=b""):
        self.name = name
        self.raw = raw

    def to_bytes(self):
        return add_headers(self.name, self.raw)

    @classmethod
    def from_bytes(cls):
        obj = cls()
        return obj


class Version(NetworkMessage):
    def __init__(self):
        super().__init__(name="version")

        self.version = (70015).to_bytes(4, "little")
        self.services = (0).to_bytes(8, "little")
        self.timestamp = int(time.time()).to_bytes(8, "little")

        # differs from https://developer.bitcoin.org/reference/p2p_networking.html#version
        self.addr_recv_services = (8).to_bytes(16, "little")

        self.addr_recv_ip_address = bytes.fromhex("0000ffff7f000001")
        self.addr_recv_port = (8333).to_bytes(2, "big")

        self.addr_trans_services = self.addr_recv_services
        self.addr_trans_ip_address = bytes.fromhex("0000ffff7f000001")
        self.addr_trans_port = (8333).to_bytes(2, "big")

        self.nonce = (0).to_bytes(8, "little")
        self.user_agent_bytes = (8).to_bytes(1, "little")
        self.user_agent = b"/Btclib/"

        self.start_height = (0).to_bytes(4, "little")
        self.relay = False.to_bytes(1, "little")

        self.raw = (
            self.version
            + self.services
            + self.timestamp
            + self.addr_recv_services
            + self.addr_recv_ip_address
            + self.addr_recv_port
            + self.addr_recv_services
            + self.addr_trans_ip_address
            + self.addr_trans_port
            + self.nonce
            + self.user_agent_bytes
            + self.user_agent
            + self.start_height
            + self.relay
        )


class Verack(NetworkMessage):
    def __init__(self):
        super().__init__(name="verack")


class Addr(NetworkMessage):
    def __init__(self):
        super().__init__(name="verack")


class Inv(NetworkMessage):
    def __init__(self):
        super().__init__(name="inv")


class Getdata(NetworkMessage):
    def __init__(self):
        super().__init__(name="getdata")


class Notfound(NetworkMessage):
    def __init__(self):
        super().__init__(name="notfound")


class Getblocks(NetworkMessage):
    def __init__(self):
        super().__init__(name="getblocks")
        self.hashes = []
        self.hash_stop = b""

    @property
    def raw(self):
        out = (70015).to_bytes(4, "little")
        out += varint.encode(len(self.hashes))
        for hash in self.hashes:
            out += hash
        out += self.hash_stop
        return out


class Getheaders(NetworkMessage):
    def __init__(self):
        super().__init__(name="getheaders")
        self.hashes = []
        self.hash_stop = b""

    @property
    def raw(self):
        out = (70015).to_bytes(4, "little")
        out += varint.encode(len(self.hashes))
        for hash in self.hashes:
            out += hash
        out += self.hash_stop
        return out


class Tx(NetworkMessage):
    def __init__(self):
        super().__init__(name="tx")


class Block(NetworkMessage):
    def __init__(self):
        super().__init__(name="block")


class Headers(NetworkMessage):
    def __init__(self):
        super().__init__(name="headers")


class Getaddr(NetworkMessage):
    def __init__(self):
        super().__init__(name="getaddr")


class Mempool(NetworkMessage):
    def __init__(self):
        super().__init__(name="mempool")


class Ping(NetworkMessage):
    def __init__(self):
        super().__init__(name="ping")
        self.nonce = random.randint(0, 2 ** 64 - 1).to_bytes(8, "little")
        self.raw = self.nonce


class Pong(NetworkMessage):
    def __init__(self):
        super().__init__(name="pong")

    def from_ping(self, ping: Ping):
        nonce = get_payload(ping)
        self.raw = nonce


class Reject(NetworkMessage):
    def __init__(self):
        super().__init__(name="reject")


class Filterload(NetworkMessage):
    def __init__(self):
        super().__init__(name="filterload")


class Filteradd(NetworkMessage):
    def __init__(self):
        super().__init__(name="filteradd")


class Filterclear(NetworkMessage):
    def __init__(self):
        super().__init__(name="filterclear")


class Merckleblock(NetworkMessage):
    def __init__(self):
        super().__init__(name="merckleblock")


class Sendheaders(NetworkMessage):
    def __init__(self):
        super().__init__(name="sendheaders")


class Freefilter(NetworkMessage):
    def __init__(self):
        super().__init__(name="freefilter")


class Sendcmpct(NetworkMessage):
    def __init__(self):
        super().__init__(name="sendcmpct")


class Cmptcblock(NetworkMessage):
    def __init__(self):
        super().__init__(name="cmptcblock")


class Getblocktxn(NetworkMessage):
    def __init__(self):
        super().__init__(name="getblocktxn")


class Blocktxn(NetworkMessage):
    def __init__(self):
        super().__init__(name="blocktxn")
