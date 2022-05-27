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



def iptables(*args, ignore_error=False):
    #print(f"iptables command: iptables {' '.join(args)}")
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
    for net in local_subnet:
        iptables("-A", "GATEKEEPER_WHITELIST", "-s", net, "-j", "ACCEPT")
    # ensure that the ports are blocked by default
    iptables("-A", "GATEKEEPER_BLOCK_PORTS", "-p", "tcp", "--match", "multiport",
            "--dport", ",".join(ports_to_block), "-j", "DROP")
    iptables("-A", "GATEKEEPER_BLOCK_PORTS", "-p", "udp", "--match", "multiport",
            "--dport", ",".join(ports_to_block), "-j", "DROP")

def open_firewall_rule_for(addr, ports):
    logging.info(f"opening the ports \"{ports}\" for GARY at {addr}")
    # Open the gatekeeping port for tcp and udp traffic comming from addr by adding them to the chain
    iptables("-A", "GATEKEEPER_TEMPORARY_LEASES", "-s", addr, "-p", "tcp", "--match", "multiport",
            "--dport", ",".join(ports), "-j", "ACCEPT")
    iptables("-A", "GATEKEEPER_TEMPORARY_LEASES", "-s", addr, "-p", "udp", "--match", "multiport",
            "--dport", ",".join(ports), "-j", "ACCEPT")

def run_server(listening_port, gatekeeping_ports, secret, acceptable_margin_ns=10_000_000_000):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", listening_port))
        # Listen for incomming connections
        while True:
            data, (addr, remote_port) = s.recvfrom(1024)
            print(f"Connected by {addr}")
            # Incorrect payload length
            if len(data) != 8 + 32:
                print(f"non-recognized message coming in from {addr}:{remote_port}")
                continue
            # Check the timestamp
            timestamp, = struct.unpack_from("<Q", data)
            now = time.time_ns()
            if timestamp < now - acceptable_margin_ns or timestamp > now + acceptable_margin_ns:
                print("not in acceptable timing window")
                continue
            # Verify the secret
            m = hashlib.sha256()
            m.update(data[:8])
            m.update(secret.encode('ascii'))
            eaten = m.digest()
            if eaten != data[8:]:
                print(f"not allowed, digest is {eaten} data is {data[8:]}")
                continue
            # Open the firewall rule for the ports
            open_firewall_rule_for(addr, gatekeeping_ports)


#def handle_args():
#    parser = ArgumentParser(description="Gatekeeper")
#    parser.add_argument('listening_port', type=int, help="udp-port this service uses to listen in to messages from the outside world")
#    parser.add_argument('protected_ports', metavar='protected_port', nargs="+", default=[], help="port that should be protected")
#    parser.add_argument('--secret', default='butts4ever', help="the secret to verify users")
#    parser.add_argument("--local-subnet", default='192.168.0.0/16', help="local subnet, this is the net on which the protected ports are always reachable from")
#    parser.add_argument('--acceptable-margin', type=float, default=10.0, help="floating point number to specify how much network delay is allowed in network/time delay in seconds")
#
#    args = parser.parse_args()
#
#    if os.geteuid() != 0:
#        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
#
#    if not args.protected_ports:
#        print("no ports to protect")
#        exit(1)
#
#    for i, port in enumerate(args.protected_ports):
#        args.protected_ports[i] = int(port)
#
#        if 0 >= args.protected_ports[i] >= 65535:
#            print(f"port {port} is not in the range 1-65535")
#            exit(1)
#    return args


# Parse one line of the config file
def parse_config_argument(args, arg):
    if (arg[0] == "port"):
        print(f"Listening on port: {arg[1]}")
        args["PORT"] = int(arg[1])
    elif (arg[0] == "prot"):
        print(f"Setting protected ports: {arg[1].split(',')}")
        args["PROT"] = list(arg[1].split(','))
    elif (arg[0] == "pass"):
        print(f"Got secret from the config")
        args["PASS"] = str(arg[1])
    elif (arg[0] == "locs"):
        print(f"Setting whitelisted ranges to: {arg[1].split(',')}")
        args["LOCS"] = list(arg[1].split(','))
    elif (arg[0] == "time"):
        print(f"Setting time margin to {arg[1]} seconds")
        args["TIME"] = int(arg[1])
    else:
        print(f"Error: Unkown config entry \"{arg[0]}\" with value \"{arg[1]}\"")
        exit(1)
    return args

# Read the config file and return the arguments
def parse_config():
    fp = open(".config", "r")
    lines = fp.readlines()
    args = {}
    for l in lines:
        l = l.strip()
        if len(l) > 1 and l[0] != '#':
            args = parse_config_argument(args, l.split('='))
    return args

def main():
    print_header()
    args = parse_config()
    #args = handle_args()
    try:
        # ports to gatekeep
        firewall_setup(args["LOCS"], args["PROT"])
        run_server(args["PORT"],
                   args["PROT"],
                   args["PASS"],
                   acceptable_margin_ns=int(args["TIME"] * 1_000_000_000))
    finally:
        # Clean up
        rm_chain("GATEKEEPER_WHITELIST")
        rm_chain("GATEKEEPER_TEMPORARY_LEASES")
        rm_chain("GATEKEEPER_BLOCK_PORTS")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
