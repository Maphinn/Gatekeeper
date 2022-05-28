#!/usr/bin/python3
import logging
import signal
import socket
import time
import struct
import hashlib
import subprocess
import os
from argparse import ArgumentParser
import sys

DEBUG = False

def print_header():
        red = '\u001b[38;5;196m'
        green = '\u001b[38;5;101m'
        clear = '\u001b[0m'
        print(f'{green} ██████╗  █████╗ ████████╗███████╗██╗  ██╗███████╗███████╗██████╗ ██████╗ ')
        print(f'██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔══██╗██╔══██╗')
        print(f'██║  ███╗███████║   ██║   █████╗  █████╔╝ █████╗  █████╗  ██████╔╝██████╔╝')
        print(f'██║   ██║██╔══██║   ██║   ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝ ██╔══██╗')
        print(f'╚██████╔╝██║  ██║   ██║   ███████╗██║  ██╗███████╗███████╗██║     ██║  ██║')
        print(f' ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝')
        print(f'                       {red}HALT, FIRST ANSWER MY RIDDLES!{clear}\n')

def dprint(*args, **kwargs):
    if DEBUG:
        green = '\u001b[38;5;101m'
        clear = '\u001b[0m'
        print(f"{green}DBG:{args[0]}{clear}")

def sigint_handler(sig, frame):
    print('Stoping gatekeeper service')
    logging.info(f"Stopping gatekeeper service")
    sys.exit(0)

def iptables(*args, ignore_error=False):
    dprint(f"iptables command: iptables {' '.join(args)}")
    result = subprocess.run(["iptables", *args], capture_output=True)

    if result.returncode != 0 and not ignore_error:
        if result.stderr != b'iptables: Chain already exists.\n':
            print("Calling iptables resulted in error!")
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

def firewall_setup(whitelist, ports):
    # Convert ports array to strings for iptables
    ports = list(map(str,ports))
    # Create the iptable chains
    create_chain_and_add_to_input("GATEKEEPER_WHITELIST")
    create_chain_and_add_to_input("GATEKEEPER_TEMPORARY_LEASES")
    create_chain_and_add_to_input("GATEKEEPER_BLOCK_PORTS")
    # Add whitelist array to the whitelist chain
    for net in whitelist:
        iptables("-A", "GATEKEEPER_WHITELIST", "-s", net, "-j", "ACCEPT")
    # Ensure that incomming traffic on the requested ports is blocked by default
    iptables("-A", "GATEKEEPER_BLOCK_PORTS", "-p", "tcp", "--match", "multiport",
            "--dport", ",".join(ports), "-j", "DROP")
    iptables("-A", "GATEKEEPER_BLOCK_PORTS", "-p", "udp", "--match", "multiport",
            "--dport", ",".join(ports), "-j", "DROP")

def open_firewall_rule_for(addr, ports):
    # Convert ports array to strings for iptables
    ports = list(map(str,ports))
    print(f"Received verified connection from \"{addr}\", granting access to the ports: \"{', '.join(ports)}\"")
    logging.info(f"Received verified connection from \"{addr}\", granting access to the ports: \"{', '.join(ports)}\"")
    # Open the gatekeeping port for tcp and udp traffic comming from addr by adding them to the chain
    iptables("-A", "GATEKEEPER_TEMPORARY_LEASES", "-s", addr, "-p", "tcp", "--match", "multiport",
            "--dport", ",".join(ports), "-j", "ACCEPT")
    iptables("-A", "GATEKEEPER_TEMPORARY_LEASES", "-s", addr, "-p", "udp", "--match", "multiport",
            "--dport", ",".join(ports), "-j", "ACCEPT")

def run_server(listening_port, gatekeeping_ports, secret, acceptable_margin_ns=10_000_000_000):
    logging.info(f"Starting gatekeeper service on port {listening_port}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", listening_port))
        # Listen for incomming connections
        while True:
            data, (addr, remote_port) = s.recvfrom(1024)
            # Incorrect payload length
            if len(data) != 8 + 32:
                print(f"Non-recognized message received from {addr}:{remote_port}")
                logging.error((f"Non-recognized message received from {addr}:{remote_port}"))
                continue
            # Check the timestamp
            timestamp, = struct.unpack_from("<Q", data)
            now = time.time_ns()
            if timestamp < now - acceptable_margin_ns or timestamp > now + acceptable_margin_ns:
                print((f"Timed-out message received from {addr}:{remote_port}"))
                logging.error((f"Timed-out message received from {addr}:{remote_port}"))
                continue
            # Verify the secret
            m = hashlib.sha256()
            m.update(data[:8])
            m.update(secret.encode('ascii'))
            eaten = m.digest()
            if eaten != data[8:]:
                print((f"Incorrect sercret received from {addr}:{remote_port}"))
                logging.error(f"Incorrect sercret received from {addr}:{remote_port}")
                continue

            # Open the firewall rule for the ports
            open_firewall_rule_for(addr, gatekeeping_ports)

# Parse one line of the config file
def parse_config_argument(args, arg):
    if (arg[0] == "port" and args.port == 8123):
        dprint(f"Listening on port: {arg[1]}")
        args.port = int(arg[1])
    elif (arg[0] == "protected" and args.protected_ports == []):
        dprint(f"Setting protected ports: {arg[1].split(',')}")
        args.protected_ports = list(arg[1].split(','))
    elif (arg[0] == "secret" and args.secret == ''):
        dprint(f"Got secret from the config")
        args.secret = str(arg[1])
    elif (arg[0] == "whitelisted" and args.whitelisted == ''):
        dprint(f"Setting whitelisted ranges to: {arg[1].split(',')}")
        args.whitelisted = list(arg[1].split(','))
    elif (arg[0] == "time" and args.time_margin == 10.0):
        dprint(f"Setting time margin to {arg[1]} seconds")
        args.time_margin = float(arg[1])
    return args

# Read the config file and return the arguments
def parse_config(args, path):
    fp = open(path + "/.config", "r")
    lines = fp.readlines()
    for l in lines:
        l = l.strip()
        if len(l) > 1 and l[0] != '#':
            args = parse_config_argument(args, l.split('='))
    return args

def handle_args():
    # Check if access to iptables is possible
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script to edit firewall rules.\nPlease try again, this time using 'sudo'. Exiting.")

    # Parse Arguments
    parser = ArgumentParser(description="Gatekeeper")
    parser.add_argument('-c', '--config',      default='', help="path of the config file")
    parser.add_argument('-s', '--secret',      default='', help="the secret to verify users")
    parser.add_argument('-w', '--whitelisted', default='', help="local subnet, this is the net on which the protected ports are always reachable from")
    parser.add_argument('-t', '--time_margin', type=float, default=10.0, help="floating point number to specify how much network delay is allowed in network/time delay in seconds")
    parser.add_argument('-p', '--port',        type=int,   default=8123, help="udp-port this service uses to listen in to messages from the outside world")
    parser.add_argument('-x', '--protected_ports', default=[], metavar='protected-ports', nargs="+", help="port that should be protected")
    args = parser.parse_args()

    # If a config path has been supplied try to parse the config
    if (args.config):
        try:
            args = parse_config(args, args.config)
        except:
            exit("Received a config path but failed to read the configuration file")

    if not args.protected_ports:
        exit("No configuration or ports to block")

    # Check the ports
    for i, port in enumerate(args.protected_ports):
        args.protected_ports[i] = int(port)
        if 0 >= args.protected_ports[i] or args.protected_ports[i] >= 65535:
            sys.exit(f"Protected port \"{port}\" is not in the range 1-65535")
    return args

def main():
    # Parse the arguments and possible configuration
    args = handle_args()   
    # Print the header
    print_header()
    # Setup logging and signal catching correctly
    logging.basicConfig(filename='gate.log', encoding='utf-8', level=logging.DEBUG, format='%(levelname)s [%(asctime)s]: %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
    signal.signal(signal.SIGINT, sigint_handler)
    try:
        # Setup the intial firewall state, creating the chains and blocking the right ports
        firewall_setup(args.whitelisted, args.protected_ports)
        # Start listening for the secret
        run_server(args.port,
                   args.protected_ports,
                   args.secret,
                   acceptable_margin_ns=int(args.time_margin * 1_000_000_000))
    finally:
        # Clean up
        rm_chain("GATEKEEPER_WHITELIST")
        rm_chain("GATEKEEPER_TEMPORARY_LEASES")
        rm_chain("GATEKEEPER_BLOCK_PORTS")

if __name__ == '__main__':
    # Setup logging settings
    main()
