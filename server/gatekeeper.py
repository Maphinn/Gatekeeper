import logging
import socket
import time
import struct
import hashlib
import subprocess
import os
from argparse import ArgumentParser

'''
The way it currently works is this.

This program now adds 3 lists to your ip-tables

GATEKEEPER_WHITELIST
GATEKEEPER_TEMPORARY_LEASES
GATEKEEPER_BLOCK_PORTS

The whitelist is a simple whitelist, by default it gets a pass for 192.168.0.0/24

The temporary_leases are the machines that have proven they know the secret of the gatekeeper!

The block ports is a list of rules to ensure the ports that are to be gate keeped are blocked if a client doesnt 
    appear in either the whitelist or the temporary leases
'''


def iptables(*args, ignore_error=False):
    print(f"iptables command: iptables {' '.join(args)}")
    result = subprocess.run(["iptables", *args], capture_output=True)

    if result.returncode != 0 and not ignore_error:
        if result.stderr != b'iptables: Chain already exists.\n':
            logging.error("Calling iptables resulted in error!")
            logging.error(result.stdout)
            logging.error(result.stderr)
            exit(1)

def rm_chain(name):
    iptables('-F', name, ignore_error=True)                # flush aka empty chain (if exists)
    iptables("-D", "INPUT", "-j", name, ignore_error=True) # remove jump from INPUT (if exists)
    iptables('-X', name, ignore_error=True)                # entirely remove chain

def create_chain_and_add_to_input(name):
    rm_chain(name)                  
    iptables("-N", name)                  # create chain
    iptables("-A", "INPUT", "-j", name)   # add jump from INPUT

def firewall_setup(local_subnet, ports_to_block):
    create_chain_and_add_to_input("GATEKEEPER_WHITELIST")
    create_chain_and_add_to_input("GATEKEEPER_TEMPORARY_LEASES")
    create_chain_and_add_to_input("GATEKEEPER_BLOCK_PORTS")

    # add local subnet to whitelist
    iptables("-A", "GATEKEEPER_WHITELIST", "-s", local_subnet, "-j", "ACCEPT")

    # ensure that the ports are blocked by default
    for port in ports_to_block:
        iptables("-A", "GATEKEEPER_BLOCK_PORTS", "-p", "tcp", "--dport", str(port), "-j", "DROP")
        iptables("-A", "GATEKEEPER_BLOCK_PORTS", "-p", "udp", "--dport", str(port), "-j", "DROP")

def open_firewall_rule_for(addr, port):
    logging.info(f"opening the port \"{port}\" for GARY at {addr}")

    # Open the gatekeeping port for tcp and udp traffic comming from addr by adding them to the chain
    iptables("-A", "GATEKEEPER_TEMPORARY_LEASES", "-s", addr, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
    iptables("-A", "GATEKEEPER_TEMPORARY_LEASES", "-s", addr, "-p", "udp", "--dport", str(port), "-j", "ACCEPT")

def run_server(listening_port, gatekeeping_ports, secret, acceptable_margin_ns=10_000_000_000):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", listening_port))

        while True:
            data, (addr, remote_port) = s.recvfrom(1024)
            print(f"Connected by {addr}")

            if len(data) != 8 + 32:
                print(f"non-recognized message coming in from {addr}:{remote_port}")
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

            for port in gatekeeping_ports:
                open_firewall_rule_for(addr, port)

def main():
    parser = ArgumentParser(description="gatekeeper")
    parser.add_argument('listening_port', type=int, help="udp-port this service uses to listen in to messages from the outside world")
    parser.add_argument('protected_ports', metavar='protected_port', nargs="+", default=[], help="port that should be protected")
    parser.add_argument('--secret', default='butts4ever', help="the secret to verify users")
    parser.add_argument("--local-subnet", default='192.168.0.0/16', help="local subnet, this is the net on which the protected ports are always reachable from")
    parser.add_argument('--acceptable-margin', type=float, default=10.0, help="floating point number to specify how much network delay is allowed in network/time delay in seconds")

    args = parser.parse_args()

    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

    if not args.protected_ports:
        print("no ports to protect")
        exit(1)

    for i, port in enumerate(args.protected_ports):
        args.protected_ports[i] = int(port)

        if 0 >= args.protected_ports[i] >= 65535:
            print(f"port {port} is not in the range 1-65535")
            exit(1) 

    try:
        # ports to gatekeep
        firewall_setup(args.local_subnet, args.protected_ports)

        red = '\u001b[38;5;196m'
        brown = '\u001b[38;5;94m'
        silver = '\u001b[38;5;249m'
        gray = '\u001b[38;5;245m'
        clear = '\u001b[0m'

        print()
        print(f'                       {red}HALT, FIRST ANSWER MY RIDDLES!{clear}')
        print()
        print(f'                             {brown}_.--X~~OO~~X--._')
        print(f'                         _.-~   / \ II / \   ~-._')
        print(f'{gray}                    {silver}[]{brown}.-~  \   /   \||/   \   /  ~-.{silver}[]')
        print(f'{gray}                _   {silver}||{brown}/     \ /     ||     \ /     \{silver}||{gray}   _')
        print(f'{gray}               (_)  {silver}|X{brown}       X      ||      X       {silver}X|{gray}  (_)')
        print(f'{gray}              _-~-_ {silver}||{brown}\     / \     ||     / \     /{silver}||{gray} _-~-_')
        print(f'{gray}              ||||| {silver}||{brown} \   /   \   /||\   /   \   / {silver}||{gray} |||||')
        print(f'{gray}              |   |_{silver}||{brown}  \ /     \ / || \ /     \ /  {silver}||{gray}_|   |')
        print(f'{gray}              |   |~{silver}||{brown}   X       X  ||  X       X   {silver}||{gray}~|   |')
        print(f'{gray}==============|   | {silver}||{brown}  / \     / \ || / \     / \  {silver}||{gray} |   |==============')
        print(f'{gray}______________|   | {silver}||{brown} /   \   /   \||/   \   /   \ {silver}||{gray} |   |______________')
        print(f'{brown}    .     .   {gray}|   | {silver}||{brown}/     \ /     ||     \ /     \{silver}||{gray} |   |{brown}  .       .')
        print(f'{brown}       /      {gray}|   | {silver}|X{brown}       X      ||      X       {silver}X|{gray} |   |{brown}    /        /')
        print(f'{brown}  /   .       {gray}|   | {silver}||{brown}\     / \     ||     / \     /{silver}||{gray} |   |{brown} .      /   .')
        print(f'{brown}.          /  {gray}|   | {silver}||{brown} \   /   \   /||\   /   \   / {silver}||{gray} |   |{brown}   .  .')
        print(f'{brown}    .    .    {gray}|   | {silver}||{brown}  \ /     \ / || \ /     \ /  {silver}||{gray} |   |{brown}          .')
        print(f'{brown}      /       {gray}|   | {silver}||{brown}   X       X  ||  X       X   {silver}||{gray} |   |{brown} . / .      /')
        print(f'{brown}  /        .  {gray}|   | {silver}||{brown}  / \     / \ || / \     / \  {silver}||{gray} |   |{brown}        /')
        print(f'{brown}         /    {gray}|   | {silver}||{brown} /   \   /   \||/   \   /   \ {silver}||{gray} |   |{brown}   .         /')
        print(f'{brown}.    .    .   {gray}|   | {silver}||{brown}/     \ /    /||\    \ /     \{silver}||{gray} |   |{brown}     /.    .')
        print(f'{brown}              {gray}|   |_{silver}|X{brown}       X    / II \    X       {silver}X|{gray}_|   |{brown}  .     .   /')
        print(f'{gray}==============|   |~II~~~~~~~~~~~~~~OO~~~~~~~~~~~~~~II~|   |==============')
        print(f"{clear}")

        run_server(args.listening_port, args.protected_ports, args.secret, acceptable_margin_ns=int(args.acceptable_margin * 1_000_000_000))
    finally:
        rm_chain("GATEKEEPER_WHITELIST")
        rm_chain("GATEKEEPER_TEMPORARY_LEASES")
        rm_chain("GATEKEEPER_BLOCK_PORTS")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    main()


