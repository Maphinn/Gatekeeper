# Gatekeeper

Gatekeeper is a simple python script that hides open ports for your server.
By listening for a specific UDP package with a secret and a timestamp,
it will open the ports upon verification for the sender IP address.

This makes it harder to detect running services on your machine.
As UDP does not keep state and no response will be given it can be hard to detect.
And the traffic to the other ports (be it UDP or TCP) is blocked and as such also produces no response.

Although it certainly helps against malware and bots scanning for open ports,
I suggest you still use something like fail2ban if you plan on using this as a defense.

### Setup

A basic setup for Gatekeeper will for example block incommming traffic to certain ports if
they are from an address that is not whitelisted.

To make this happen a little setup is required.
For safety reasons it is advised that you run "iptables-save" and store the output.
Just in case you mess up and want a quick way to revert the changes.

//
//Then make sure you drop all traffic from any of the targets you wish to be guarded for.
//(Or even better make a whitelist for addresses that you trust as in the case the LAN networks.)
//
//    iptables -N GATE_WHITELIST
//    iptables -A INPUT -j GATE_WHITELIST
//    iptables -A GATE_WHITELIST -s 10.0.0.0/16    -j ACCEPT
//    iptables -A GATE_WHITELIST -s 192.168.0.0/16 -j ACCEPT
//
//The code above creates a chain that whitelists incomming connections from the local area networks 10.0.0.0 and 192.168.0.0 with the subnetmask 255.255.0.0 and adds the chain to be executed on all incoming traffic.
//IMPORTANT, make sure that you whitelist your own IP if you are working remotely.
//Next up we need to make sure that any received input that is not whitelisted is dropped.
//
//    iptables -P INPUT DROP
//
//This might break other things if you are currently exposing things to the outside world so be carefull.
//
//One lasts suggestion is to make sure that the sessions are temporary.
//To make sure the session are temporary be sure to add the folowing as daily cron rule:
//
//    00 02 * * * iptables -F GATEKEEPER
//
//This will remove all the currently allowed sessions at the end of the day by flushing the iptable chain.
//
//### Restoring the iptables
//
//If you wish to revert the iptables back to before using Gatekeeper,
//you will have to make sure you 
//To remove all the rules and the chain you can run:
//
//    iptables -F GATEKEEPER
//    iptables -D INPUT -j GATEKEEPER
//    iptables -X GATEKEEPER
//
//### Notes:
//
//Garry has stolen your lawnmower for the last time.
//Keep gary out by closing the gate to your server which hosts the lawnmower daemon.
//Stay out of my shed Garry!

### Service
To make gatekeeper run when the machine starts one can use systemd services.
First you will need to edit the example service file.
Changing the path for python, the path for the location of the gatekeeper script
and adding any arguments you want to run the script with.
Then proceed to copy the edited file to /etc/systemd/system/gatekeeper.service.
Finally you will need to run the following commands:

    systemctl daemon-reload
    systemctl enable gatekeeper.service
    systemctl start gatekeeper.service

You can use the command below to check if the script was able to start correctly.

    systemctl status gatekeeper.service

### Todo:
- [x] Add config file support
- [x] Debug print
- [x] Service functionality and how to enable
- [ ] Rewrite argparse to support overloading and or substituting the config file
- [x] Add logging capabilties
- [ ] Catch sigint
- [ ] Add sender addr to sercret hash as salt to prevent replay attacks in small time window?
- [ ] Rewrite the README file with the correct instructions
