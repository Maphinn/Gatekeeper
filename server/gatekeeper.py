import socket
import time
import struct
import hashlib
import subprocess
from argparse import ArgumentParser 

def firewall_setup():
    # Flush the GATEKEEPER chain if it already exists
    subprocess.run(["iptables", "-F", "GATEKEEPER"])
    # Create the GATEKEEPER chain in case it doesn't exist
    subprocess.run(["iptables", "-N", "GATEKEEPER"])
    # Remove the chain jump to prevent duplicates if it exists
    subprocess.run(["iptables", "-D", "INPUT", "-j", "GATEKEEPER"])
    # Add the chain jump to GATEKEEPER at the end of the INPUT chain
    subprocess.run(["iptables", "-A", "INPUT", "-j", "GATEKEEPER"])

def open_firewall_rule_for(addr, port):
    print(f"opening the port \"{port}\" for GARY at {addr[0]}")
    # Open the gatekeeping port for tcp and udp traffic comming from addr by adding them to the chain
    subprocess.run(["iptables", "-A", "GATEKEEPER", "-s", addr[0], "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    subprocess.run(["iptables", "-A", "GATEKEEPER", "-s", addr[0], "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])

def run_server(listening_port, gatekeeping_port, secret, acceptable_margin_ns=10_000_000_000):
    firewall_setup()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", listening_port))

        while True:
            data, addr = s.recvfrom(1024)
            print(f"Connected by {addr}")

            if len(data) != 8 + 32:
                print(f"non-recognized message coming in from {addr}")
                continue

            timestamp, = struct.unpack_from("<Q", data)
            now = time.time_ns()

            print(f'timestamp now: {now} timestamp gotten: {timestamp}')

            if timestamp < now - acceptable_margin_ns or timestamp > now + acceptable_margin_ns:
                print("not in acceptable timing window")
                continue

            m = hashlib.sha256()
            m.update(data[:8])
            m.update(secret.encode('ascii'))

            eaten = m.digest()

            if eaten != data[8:]:
                print(f"not allowed, digest is {eaten} data is {data[8:]}")
                continue

            open_firewall_rule_for(addr, gatekeeping_port)


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
