import socket
import time
import sys


a = sys.argv[1]

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 18888  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        # s.sendall(random.randint(1, 2 ** 16 - 1).to_bytes(16, "little"))
        s.sendall((str(a) * 10).encode())
        data = s.recv(1024)
        print("Received", repr(data))
        time.sleep(0.5)
