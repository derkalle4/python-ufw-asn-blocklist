# python-ufw-asn-blocklist
This tool blocks or allows a given list of ASNs inside UFW to avoid unnecessary attack space. I created this small tool to fill the gap of other tools which somewhat do the same - but either only with IP-Tables or with ufw insert which takes a long time (injecting only about two IP addresses per second).

This approach creates a new user.rules and user6.rules in the root folder of this repository which could be simply copied by hand into the RULES section of the /etc/ufw/*.rules - you can also automate this step by running this script as root (which is not recommended, but I am lazy and trust my own code).

It will NOT reload the firewall automatically. You still need to do this with "ufw reload" in the command line.

Current status: under development. Only asn_allow_lists and asn_deny_lists are implemented. See the example settings.yaml