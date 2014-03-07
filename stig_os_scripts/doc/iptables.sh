#!/bin/bash
################
# Modify this file accordingly for site specific requirements.

# http://www.thegeekstuff.com
# 1. Delete all existing rules
iptables -F

# 2. Set default chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 3. Block a specific ip-address
#BLOCK_THIS_IP="x.x.x.x"
#iptables -A INPUT -s "$BLOCK_THIS_IP" -j DROP

# 4. Allow ALL incoming SSH
iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# 6. Allow incoming HTTP
iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Allow incoming geoserver
iptables -A INPUT -i eth0 -p tcp --dport 8080 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 8080 -m state --state ESTABLISHED -j ACCEPT

# 8. Allow outgoing SSH
#iptables -A OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# 10. Allow outgoing HTTP
iptables -A OUTPUT -o eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# 10. Allow outgoing HTTPS
iptables -A OUTPUT -o eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# 12. Ping from inside to outside
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# 14. Allow loopback access
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 16. Allow outbound DNS
iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT

# Similar to #19 -> Allow PostgreSQL connection only from a specific network
iptables -A OUTPUT -o eth0 -p tcp -d rogue-database --dport 5432 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp -s rogue-database --sport 5432 -m state --state ESTABLISHED -j ACCEPT

# 23. Prevent DoS attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Drop udplite packets
iptables -A INPUT -p udplite -j DROP

# Allow NTP - modify for site specific.  These are tied to the default ntp servers added with the script.
iptables -A OUTPUT -p udp -d ntp2.usno.navy.mil -m udp -j ACCEPT
iptables -A INPUT -p udp -s ntp2.usno.navy.mil -m udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p udp -d ntp-s1.cise.ufl.edu -m udp -j ACCEPT
iptables -A INPUT -p udp -s ntp-s1.cise.ufl.edu -m udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p udp -d ntp.colby.edu -m udp -j ACCEPT
iptables -A INPUT -p udp -s ntp.colby.edu -m udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p udp -d tick.usno.navy.mil -m udp -j ACCEPT
iptables -A INPUT -p udp -s tick.usno.navy.mil -m udp --dport 123 -j ACCEPT

# Allow freshclam to update the anti-virus database. Modify as appropriate for anti-virus software changes.
iptables -A OUTPUT -o eth0 -p tcp --sport 1024:65535 -d 150.214.142.197 --dport 80 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -s 150.214.142.197 --dport 1024:65535 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -d 150.214.142.197 --dport 1024:65535 -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -d 150.214.142.197 --dport 1024:65535 -j ACCEPT

iptables -A OUTPUT -o eth0 -p tcp --sport 1024:65535 -d 69.163.100.14 --dport 80 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -s 69.163.100.14 --dport 1024:65535 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -d 69.163.100.14 --dport 1024:65535 -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -d 69.163.100.14 --dport 1024:65535 -j ACCEPT

# 25. Log dropped packets
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A OUTPUT -j LOGGING
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables Packet Dropped: " --log-level 7
iptables -A LOGGING -j DROP

###############
