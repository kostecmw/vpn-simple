#!/bin/bash

set -a
source .env
set +a

./vpn-server-simple -mode server -local :51820 -remote "$CLIENT_IP:51821" -tun tun0