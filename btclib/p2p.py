#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from . import messages
import socket
import threading

PORT = 18888


class Connection(threading.Thread):
    def __init__(self, socket, network_string="f9beb4d9"):
        super().__init__()
        self.socket = socket
        self.terminate_flag = threading.Event()
        self.network_string = bytes.fromhex(network_string)
        self.messages = []
        self.buffer = b""

    def send(self, data: messages.NetworkMessage):
        self.socket.sendall(self.network_string + data)

    def stop(self):
        self.terminate_flag.set()

    def parse_messages(self):
        msgs = self.buffer.split(self.network_string)[1:]
        for i, msg in enumerate(msgs):
            msg = self.network_string + msg
            try:
                messages.verify_headers(msg)
                self.messages.append(messages.get_payload(msg))
                self.buffer = self.buffer[len(msg) :]
            except Exception:
                if i != len(msgs) - 1:
                    self.buffer = self.buffer[len(msg) :]

    def run(self):
        self.socket.settimeout(10.0)

        while not self.terminate_flag.is_set():
            try:
                line = self.socket.recv(4096)
                # if line:
                #     print(line)
                self.buffer += line
                self.parse_messages()
            except socket.timeout:
                # self.main_node.debug_print("NodeConnection: timeout")
                pass
            except Exception:
                self.terminate_flag.set()


class Node:
    def __init__(self):
        self.network_string = "f9beb4d9"
        self.conn = self.connect("89.71.41.165")

    def connect(self, ip, port=8333) -> Connection:
        TCP_IP = ip
        TCP_PORT = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT))

        conn = Connection(s, self.network_string)
        conn.start()

        version = messages.Version()
        conn.send(version.to_bytes())

        verack = messages.Verack()
        conn.send(verack.to_bytes())

        return conn

    def run(self):
        pass

    def send(self, data: messages.NetworkMessage):
        self.conn.send(data)


BUFFER_SIZE = 1024

from . import messages, blocks
import time


def download_block(block_hash):
    node = Node()
    a = messages.NetworkMessage(
        "getdata", b"\x01\x02\x00\x00@" + bytes.fromhex(block_hash)[::-1]
    )
    node.send(a.to_bytes())
    time.sleep(2)
    # block_bytes = node.conn.messages[-1][1]
    i = 0
    while True:
        i += 1
        raw = node.conn.messages[-i]
        if raw[0] == b"block":
            block_bytes = raw[1]
            break
    block = blocks.deserialize_block(block_bytes)
    node.conn.stop()
    return block


# len(download_block('')['transactions'])

# node = Node()
#
# a = messages.Ping()
# node.send(a.to_bytes())

# b = messages.Getblocks()
# node.send(b.to_bytes())
#
# import time
#
# time.sleep(1)
#
# b = messages.NetworkMessage("getdata", node.conn.messages[-1][1])
#
# node.send(b.to_bytes())
