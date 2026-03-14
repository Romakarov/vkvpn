#!/bin/bash
# Add routes to TURN servers via default gateway
# Usage: ./client ... | sudo bash routes.sh
gateway="$(ip -o -4 route show to default | awk '/via/ {print $3}' | head -1)"
while read -r remote; do
  sudo ip r add "$remote" via "$gateway" 2>/dev/null || true
done
