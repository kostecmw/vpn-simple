#!/bin/bash

set -a
source .env
set +a

sudo ip route del 10.0.0.0/24

ip addr add 10.0.0.2/24 dev tun1
ip link set tun1 up
ip link set tun1 mtu 1400

ip route add "$SERVER_IP" via 192.168.88.1 dev wlp2s0
ip route del default via 192.168.88.1
ip route add default via 10.0.0.1 dev tun1