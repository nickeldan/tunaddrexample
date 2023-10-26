#!/bin/sh -ex

./emit &
pid=$!

sleep 1

iptables -I FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -I FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE

trigger_emit() {
    while sleep 1; do
        kill -s USR1 $pid
    done
}

trigger_emit &

tcpdump -i any -n
