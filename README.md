# Gatekeeper

Gatekeeper is a simple pythons script that hides an open port for your server.
By listening for a specific UDP package with a secret it will open the port for the sender IP.

### Setup
To setup the gatekeeper you will need to drop the tcp and udp inputs in your iptables.
To make sure the session are temporary be sure to add the folowing as daily cron rule:

    iptables -F GATEKEEPER

To remove all the rules and the chain you can run:

    iptables -F GATEKEEPER && iptables -D INPUT -j GATEKEEPER && iptables -X GATEKEEPER

### Notes:
Stay out of my shed Garry!


