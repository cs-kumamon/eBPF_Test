#!/usr/bin/env bash
set -euo pipefail

ip link del veth0 2>/dev/null || true
ip link del veth1 2>/dev/null || true

ip link add veth0 type veth peer name ex_veth0
ip link add veth1 type veth peer name ex_veth1

ip addr add 10.10.1.1/24 dev veth0
ip addr add 10.10.1.254/24 dev ex_veth0

ip addr add 10.10.2.1/24 dev veth1
ip addr add 10.10.2.254/24 dev ex_veth1

ip link set veth0 up
ip link set ex_veth0 up
ip link set veth1 up
ip link set ex_veth1 up

sysctl -w net.ipv4.ip_forward=1 >/dev/null

mac0=$(ip -o link show ex_veth0 | awk '{print $17}')
mac1=$(ip -o link show ex_veth1 | awk '{print $17}')

ip neigh replace 10.10.1.254 lladdr "$mac0" dev veth0 nud permanent
ip neigh replace 10.10.2.254 lladdr "$mac1" dev veth1 nud permanent

echo "veth setup complete"
