# Gatekeeper

Gatekeeper is a simple pythons script that hides an open port for your server.
By listening for a specific UDP package with a secret it will open the port for the sender IP.

### Setup

A basic setup for Gatekeeper will for example block all traffic not from a LAN.
And then proceed hide a port from any traffic from outside the LAN.
To make this happen a little setup is required.

First have lunch.

Then make sure you drop all traffic from any of the targets you wish to be guarded for.
(Or even better make a whitelist for addresses that you trust as in the case the LAN networks.)

    iptables -N GATE_WHITELIST
    iptables -A INPUT -j GATE_WHITELIST
    iptables -A GATE_WHITELIST -s 10.0.0.0/16    -j ACCEPT
    iptables -A GATE_WHITELIST -s 192.168.0.0/16 -j ACCEPT

The code above creates a chain that whitelists incomming connections from the local area networks 10.0.0.0 and 192.168.0.0 with the subnetmask 255.255.0.0 and adds the chain to be executed on all incoming traffic.
IMPORTANT, make sure that you whitelist your own IP if you are working remotely.
Next up we need to make sure that any received input that is not whitelisted is dropped.

    iptables -P INPUT DROP

This might break other things if you are currently exposing things to the outside world so be carefull.

One lasts suggestion is to make sure that the sessions are temporary.
To make sure the session are temporary be sure to add the folowing as daily cron rule:

    00 02 * * * iptables -F GATEKEEPER

This will remove all the currently allowed sessions at the end of the day by flushing the iptable chain.

### Restoring the iptables

If you wish to revert the iptables back to before using Gatekeeper,
you will have to make sure you 
To remove all the rules and the chain you can run:

    iptables -F GATEKEEPER
    iptables -D INPUT -j GATEKEEPER
    iptables -X GATEKEEPER

### Notes:

Garry has stolen your lawnmower for the last time.
Keep gary out by closing the gate to your server which hosts the lawnmower daemon.
Stay out of my shed Garry!


