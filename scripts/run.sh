#!/usr/bin/env bash
set -euo pipefail

make -s

attach_dev="${ATTACH_DEVS:-}"
if [ -z "${attach_dev}" ]; then
  attach_dev=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
fi
if [ -z "${attach_dev}" ]; then
  attach_dev="veth0,veth1"
fi

./tc_router --watch \
  --attach-devs "${attach_dev}" \
  --devs veth0,veth1 \
  --route 10.10.1.1@10.10.1.254@veth0 \
  --route 10.10.2.1@10.10.2.254@veth1

echo "tc bpf policy routing loaded"
