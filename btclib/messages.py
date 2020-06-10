#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
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
from typing import Tuple, TypedDict, Union
from collections import defaultdict

from .alias import Octets
from .utils import bytes_from_octets

from . import varint


# does not add network_string
def add_headers(name: str, payload: bytes) -> bytes:
    command = name + ((12 - len(name)) * "\00")
    payload_len = struct.pack("I", len(payload))
    checksum = sha256(sha256(payload).digest()).digest()[:4]
    return command.encode() + payload_len + checksum + payload


def verify_headers(message: bytes) -> bool:
    payload_len = int.from_bytes(message[16:20], "little")
    checksum = message[20:24]
    payload = message[24:]
    if len(payload) != payload_len:
        raise Exception("Wrong payload length")
    if checksum != sha256(sha256(payload).digest()).digest()[:4]:
        raise Exception("Wrong checksum, the message might have been tampered")

    return True


def get_message_payload(message: bytes) -> bytes:
    try:
        verify_headers(message)
    except Exception:
        raise Exception("Incorrect headers")
    payload = message[24:]

    return payload


def get_message_name(message: bytes) -> str:
    try:
        verify_headers(message)
    except Exception:
        raise Exception("Incorrect headers")
    message_name = message[4:16].rstrip(b"\x00").decode()

    return message_name


class Version(TypedDict):
    version: int  # = 70015
    services: int  # = 0 or 8 for witness
    timestamp: int  # = int(time.time())

    # differs from https://developer.bitcoin.org/reference/p2p_networking.html#version
    addr_recv_services: int  # = 0
    addr_recv_ip_address: str  # = "0000ffff7f000001"
    addr_recv_port: int  # = 8333

    addr_trans_services: int  # = addr_recv_services
    addr_trans_ip_address: str  # = "0000ffff7f000001"
    addr_trans_port: int  # = 8333

    nonce: int  # = 0
    user_agent: str  # = "/Btclib/"
    start_height: int  # = 0
    relay: bool  # = False


def deserialize_version(data: Octets) -> Version:
    data = bytes_from_octets(data)
    name = get_message_name(data)
    if name != "version":
        raise Exception("Invalid message type")
    data = get_message_payload(data)
    ver = int.from_bytes(data[:4], "little")
    data = data[4:]
    services = int.from_bytes(data[:8], "little")
    data = data[8:]
    timestamp = int.from_bytes(data[:8], "little")
    data = data[8:]
    addr_recv_services = int.from_bytes(data[:16], "little")
    data = data[16:]
    addr_recv_ip_address = data[:8].hex()
    data = data[8:]
    addr_recv_port = int.from_bytes(data[:2], "little")
    data = data[2:]
    addr_trans_services = int.from_bytes(data[:16], "little")
    data = data[16:]
    addr_trans_ip_address = data[:8].hex()
    data = data[8:]
    addr_trans_port = int.from_bytes(data[:2], "little")
    data = data[2:]
    nonce = int.from_bytes(data[:8], "little")
    data = data[8:]
    user_agent_length = varint.decode(data)
    data = data[len(varint.encode(user_agent_length)) :]
    user_agent = data[:user_agent_length].hex()
    data = data[user_agent_length:]
    start_height = int.from_bytes(data[:4], "little")
    data = data[4:]
    relay = bool(int.from_bytes(data[0], "little"))
    version: Version = {
        "version": ver,
        "services": services,
        "timestamp": timestamp,
        "addr_recv_services": addr_recv_services,
        "addr_recv_ip_address": addr_recv_ip_address,
        "addr_recv_port": addr_recv_port,
        "addr_trans_services": addr_trans_services,
        "addr_trans_ip_address": addr_trans_ip_address,
        "addr_trans_port": addr_trans_port,
        "nonce": nonce,
        "user_agent": user_agent,
        "start_height": start_height,
        "relay": relay,
    }
    return version


def serialize_version(version: Version) -> bytes:
    out = version["version"].to_bytes(4, "little")
    out += version["services"].to_bytes(8, "little")
    out += version["timestamp"].to_bytes(8, "little")
    out += version["addr_recv_services"].to_bytes(16, "little")
    out += bytes.fromhex(version["addr_recv_ip_address"])
    out += version["addr_recv_port"].to_bytes(2, "little")
    out += version["addr_trans_services"].to_bytes(16, "little")
    out += bytes.fromhex(version["addr_trans_ip_address"])
    out += version["addr_trans_port"].to_bytes(2, "little")
    out += version["nonce"].to_bytes(8, "little")
    out += varint.encode(len(version["user_agent"]))
    out += varint["user_agent"].encode()
    out += version["start_height"].to_bytes(4, "little")
    out += version["relay"].to_bytes(1, "little")
    return add_headers("version", out)


class Verack(TypedDict):
    pass


def deserialize_verak(data: Octets) -> Version:
    data = bytes_from_octets(data)
    name = get_message_name(data)
    if name != "verack":
        raise Exception("Invalid message type")
    return Verack()


def serialize_verak(verack: Verack) -> bytes:
    return add_headers("verack", b"")


# class Verack(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="verack")
#
#
# class Addr(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="verack")
#
#
# class Inv(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="inv")
#
#
# class Getdata(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="getdata")
#
#
# class Notfound(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="notfound")
#
#
# class Getblocks(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="getblocks")
#         self.hashes = []
#         self.hash_stop = b""
#
#     @property
#     def raw(self):
#         out = (70015).to_bytes(4, "little")
#         out += varint.encode(len(self.hashes))
#         for hash in self.hashes:
#             out += hash
#         out += self.hash_stop
#         return out
#
#
# class Getheaders(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="getheaders")
#         self.hashes = []
#         self.hash_stop = b""
#
#     @property
#     def raw(self):
#         out = (70015).to_bytes(4, "little")
#         out += varint.encode(len(self.hashes))
#         for hash in self.hashes:
#             out += hash
#         out += self.hash_stop
#         return out
#
#
# class Tx(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="tx")
#
#
# class Block(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="block")
#
#
# class Headers(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="headers")
#
#
# class Getaddr(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="getaddr")
#
#
# class Mempool(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="mempool")


class Ping(TypedDict):
    nonce: int


def deserialize_ping(data: Octets) -> Ping:
    data = bytes_from_octets(data)
    name = get_message_name(data)
    if name != "ping":
        raise Exception("Invalid message type")
    data = get_message_payload(data)
    nonce = int.from_bytes(data[:8], "little")
    ping: Ping = {"nonce": nonce}
    return ping


def serialize_ping(ping: Ping) -> bytes:
    nonce = ping["nonce"].to_bytes(8, "little")
    return add_headers("ping", nonce)


class Pong(TypedDict):
    nonce: int


def deserialize_pong(data: Octets) -> Pong:
    data = bytes_from_octets(data)
    name = get_message_name(data)
    if name != "pong":
        raise Exception("Invalid message type")
    data = get_message_payload(data)
    nonce = int.from_bytes(data[:8], "little")
    pong: Pong = {"nonce": nonce}
    return pong


def serialize_pong(pong: Pong) -> bytes:
    nonce = pong["nonce"].to_bytes(8, "little")
    return add_headers("pong", nonce)


#
#
# class Reject(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="reject")
#
#
# class Filterload(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="filterload")
#
#
# class Filteradd(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="filteradd")
#
#
# class Filterclear(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="filterclear")
#
#
# class Merckleblock(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="merckleblock")
#
#
# class Sendheaders(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="sendheaders")
#
#
# class Freefilter(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="freefilter")
#
#
# class Sendcmpct(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="sendcmpct")
#
#
# class Cmptcblock(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="cmptcblock")
#
#
# class Getblocktxn(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="getblocktxn")
#
#
# class Blocktxn(NetworkMessage):
#     def __init__(self):
#         super().__init__(name="blocktxn")

Message = Union[Version, Verack, Ping, Pong]


def deserialize(data: bytes) -> Message:
    data = bytes_from_octets(data)
    name = get_message_name(data)
    if name == "version":
        return deserialize_version(data)
    elif name == "verack":
        return deserialize_verak(data)
    elif name == "ping":
        return deserialize_ping(data)
    elif name == "pong":
        return deserialize_pong(data)
    else:
        raise Exception()


def serialize(msg: Message) -> bytes:
    if isinstance(msg, Version):
        return serialize_version(msg)
    elif isinstance(msg, Verack):
        return serialize_verak(msg)
    elif isinstance(msg, Ping):
        return serialize_ping(msg)
    elif isinstance(msg, Pong):
        return serialize_pong(msg)
