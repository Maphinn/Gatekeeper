import socket
import time
import struct
import hashlib
from argparse import ArgumentParser 

def open_firewall_rule_for(addr):
    print(f"opening the port for GARY at {addr}")

def run_server(listening_port, gatekeeping_port, secret, acceptable_margin_ns=10_000):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", listening_port))

        while True:
            data, addr = s.recvfrom(1024)
            print(f"Connected by {addr}")

            if len(data) != 8 + 32:
                print(f"non-recognized message coming in from {addr}")

            timestamp, = struct.unpack_from("<Q", data)
            now = time.time_ns()

            print(f'timestamp now: {now} timestamp gotten: {timestamp}')

            if timestamp < now - acceptable_margin_ns or timestamp > now + acceptable_margin_ns:
                print("not in acceptable timing window")
                continue

            m = hashlib.sha256()
            m.update(data[:8])
            m.update(secret)

            if m.digest() != data[8:]:
                continue
            
            open_firewall_rule_for(addr)


def main():
    parser = ArgumentParser(description="gatekeeper")
    parser.add_argument('listening_port', type=int, help="udp-port this service uses to listen in to messages from the outside world")
    parser.add_argument('gatekeeping_port', type=int, help="port that should be protected")
    parser.add_argument('secret', help="the secret to verify users")

    args = parser.parse_args()

    print("running gatekeeperrrr")
    run_server(args.listening_port, args.gatekeeping_port, args.secret)

if __name__ == '__main__':
    main()