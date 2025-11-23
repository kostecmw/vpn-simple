#!/bin/bash

set -a
source .env
set +a

./vpn-client-simple -mode client -local :51821 -remote "$SERVER_IP:51820" -tun tun1