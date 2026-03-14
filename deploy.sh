#!/bin/bash
# Deploy VKVPN server to VPS
# Usage: ./deploy.sh root@144.124.247.27
set -e

if [ -z "$1" ]; then
  echo "Usage: ./deploy.sh user@host"
  echo "Example: ./deploy.sh root@144.124.247.27"
  exit 1
fi

HOST="$1"

echo "Building server binary..."
cd "$(dirname "$0")"
GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o /tmp/vkvpn-server ./server/

echo "Uploading to $HOST..."
scp /tmp/vkvpn-server "$HOST:/opt/vkvpn/server"
scp install.sh "$HOST:/tmp/vkvpn-install.sh"

echo "Running install script..."
ssh "$HOST" 'bash /tmp/vkvpn-install.sh && systemctl restart vkvpn'

echo ""
echo "Deployment complete!"
echo "Check: ssh $HOST 'systemctl status vkvpn'"
