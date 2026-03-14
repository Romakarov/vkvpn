#!/bin/bash
# VKVPN Client — Mac/Linux one-liner
# Usage: ./connect-mac.sh
set -e

CONFIG_FILE="$HOME/.vkvpn.conf"

# Load or ask for config
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
fi

if [ -z "$PEER" ]; then
  echo "=== VKVPN Setup ==="
  read -p "VPS address (host:port, e.g. 144.124.247.27:56000): " PEER
  read -p "VK link OR Yandex link: " LINK
  read -p "Number of connections (16 for VK, 1 for Yandex, default 16): " CONNS
  CONNS=${CONNS:-16}

  # Detect provider
  if echo "$LINK" | grep -qi "vk\|join"; then
    PROVIDER="vk"
    LINK_FLAG="-vk-link"
  else
    PROVIDER="yandex"
    LINK_FLAG="-yandex-link"
  fi

  # Save config
  cat > "$CONFIG_FILE" <<EOF
PEER="$PEER"
LINK="$LINK"
LINK_FLAG="$LINK_FLAG"
PROVIDER="$PROVIDER"
CONNS="$CONNS"
EOF
  echo "Config saved to $CONFIG_FILE"
  echo ""
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$SCRIPT_DIR/../client-bin"

# Build if needed
if [ ! -f "$CLIENT" ]; then
  echo "Building client..."
  cd "$SCRIPT_DIR/.."
  go build -ldflags '-s -w' -trimpath -o client-bin ./client/
  CLIENT="$SCRIPT_DIR/../client-bin"
  cd "$SCRIPT_DIR"
fi

echo "=== VKVPN ==="
echo "Provider: $PROVIDER"
echo "Peer:     $PEER"
echo "Listen:   127.0.0.1:9000"
echo ""
echo "Configure WireGuard:"
echo "  Endpoint = 127.0.0.1:9000"
echo "  MTU = 1280"
echo ""
echo "Starting tunnel... (Ctrl+C to stop)"
echo ""

# On Mac, add routes for TURN servers
if [[ "$OSTYPE" == "darwin"* ]]; then
  GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
  "$CLIENT" $LINK_FLAG "$LINK" -peer "$PEER" -n "$CONNS" -listen 127.0.0.1:9000 2>&1 | while read -r line; do
    echo "$line"
    # If line looks like an IP, add route
    if echo "$line" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      sudo route -n add "$line/32" "$GW" 2>/dev/null || true
    fi
  done
else
  "$CLIENT" $LINK_FLAG "$LINK" -peer "$PEER" -n "$CONNS" -listen 127.0.0.1:9000 2>&1 | while read -r line; do
    echo "$line"
    if echo "$line" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      GW=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)
      sudo ip route add "$line/32" via "$GW" 2>/dev/null || true
    fi
  done
fi
