#!/usr/bin/env bash
set -euo pipefail

make -s

cfg="${CONFIG:-config/tc_router.conf}"
attach_egress="${ATTACH_EGRESS_DEVS:-}"
if [ -z "${attach_egress}" ]; then
  attach_egress=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
fi

if [ -n "${attach_egress}" ]; then
  tmp_cfg=$(mktemp)
  sed "s/^attach_egress_devs=.*/attach_egress_devs=${attach_egress}/" "${cfg}" > "${tmp_cfg}"
  ./tc_router --config "${tmp_cfg}"
  rm -f "${tmp_cfg}"
else
  ./tc_router --config "${cfg}"
fi

echo "tc bpf policy routing loaded"
