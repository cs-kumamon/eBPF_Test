#!/usr/bin/env bash
set -euo pipefail

#if [ -x ./tc_router ]; then
#  ./tc_router --config config/tc_router_detach.conf
#fi

ip link del veth0 2>/dev/null || true
ip link del veth1 2>/dev/null || true

sudo ip addr del 10.10.1.1/24 dev enp0s3
sudo ip addr del 10.10.1.2/24 dev enp0s3

echo "cleanup done"
