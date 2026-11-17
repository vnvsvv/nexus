#!/usr/bin/env bash
# Benign noise generator for false-positive measurement (Linux). Run for N minutes: ./noise.sh 60
# Expected NEXUS outcome: zero incidents. Every incident raised during a noise-only run is a false positive.
MIN=${1:-30}; TARGET=${NEXUS_TARGET:-192.168.20.10}
end=$((SECONDS + MIN*60))
while [ $SECONDS -lt $end ]; do
  ls -la /usr/share >/dev/null
  grep -r "nexus" /etc/hostname >/dev/null 2>&1
  cp /etc/hostname /tmp/noise-$RANDOM && rm -f /tmp/noise-*
  python3 -c "import json; print(json.dumps({'ok':1}))" >/dev/null
  curl -s -m 3 -o /dev/null "http://${TARGET}:8443/" || true
  bash -c "echo benign > /tmp/.n && cat /tmp/.n" >/dev/null
  sleep $((2 + RANDOM % 8))
done
