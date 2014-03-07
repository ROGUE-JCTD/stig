#!/bin/bash
################
# Modify this file accordingly for your specific requirement.

# http://www.thegeekstuff.com

iptables-save -c > saved-iptables.rules

# 1. Delete all existing rules
iptables -F

# 2. Set default chain policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -X LOGGING

###############
