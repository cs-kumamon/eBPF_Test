#!/usr/bin/env bash
set -euo pipefail

if [ -x ./tc_router ]; then
  ./tc_router --detach --devs veth0,veth1 || true
fi

ip link del veth0 2>/dev/null || true
ip link del veth1 2>/dev/null || true

echo "cleanup done"
