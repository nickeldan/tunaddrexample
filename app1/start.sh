#!/bin/sh -ex

./emit

iptables -I FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -I FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE

tcpdump -i any -n
