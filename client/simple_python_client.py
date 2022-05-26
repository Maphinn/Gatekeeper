from argparse import ArgumentParser

import socket
import time
import struct
import hashlib

def enable_ssh_port(ip, port, secret):
    # Create UDP sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    timestamp = time.time_ns()
    m = hashlib.sha256()

    # sha256(timestamp || secret)
    m.update(struct.pack("<Q", timestamp))
    m.update(secret.encode('ascii'))

    sock.sendto(struct.pack("<Qp", timestamp, m.digest()), (ip, port))

def main():
    parser = ArgumentParser(description="simple unlocking client")
    parser.add_argument('server', help="the ip of the remote server")
    parser.add_argument('port', type=int, help="the port of the remote server's gatekeeper program")
    parser.add_argument('secret', help="the secret used, to unlock the gatekeeper")

    args = parser.parse_args()

    enable_ssh_port(args.server, args.port, args.secret)

if __name__ == '__main__':
    main()