#!/bin/bash
# VKVPN Server Install Script for Ubuntu 24.04
# Run as root: bash install.sh
set -e

echo "=== VKVPN Server Installer ==="

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

# Detect server IP
SERVER_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
echo "Server IP: $SERVER_IP"

# Detect main network interface
IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
echo "Network interface: $IFACE"

# Install dependencies
echo "Installing WireGuard and dependencies..."
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools qrencode

# Enable IP forwarding
echo "Enabling IP forwarding..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1

# Create directories
mkdir -p /etc/vkvpn
mkdir -p /opt/vkvpn

# Generate WireGuard keys if not exist
if [ ! -f /etc/vkvpn/config.json ]; then
  WG_PRIV=$(wg genkey)
  WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
  ADMIN_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)

  # Hash password with bcrypt via python3 (use $2a$ prefix for Go compatibility)
  ADMIN_HASH=$(python3 -c "
import bcrypt
h = bcrypt.hashpw(b'${ADMIN_PASS}', bcrypt.gensalt()).decode()
# Go's x/crypto/bcrypt only accepts \$2a\$ prefix, not \$2b\$
print(h.replace('\$2b\$', '\$2a\$', 1))
" 2>/dev/null || echo "")

  cat > /etc/vkvpn/config.json <<CONF
{
  "server_ip": "$SERVER_IP",
  "wg_port": 51820,
  "wg_subnet": "10.66.66.0/24",
  "server_private_key": "$WG_PRIV",
  "server_public_key": "$WG_PUB",
  "dns": "1.1.1.1, 8.8.8.8",
  "dtls_port": 56000,
  "admin_pass_hash": "$ADMIN_HASH",
  "active_link": "",
  "link_type": "",
  "clients": []
}
CONF
  chmod 600 /etc/vkvpn/config.json
  echo "Config created: /etc/vkvpn/config.json"
  echo "Admin password: $ADMIN_PASS"
else
  echo "Config already exists, skipping..."
  ADMIN_PASS=$(python3 -c "import json; print(json.load(open('/etc/vkvpn/config.json'))['admin_pass'])" 2>/dev/null || echo "check config")
fi

# Create initial WireGuard config
WG_PRIV=$(python3 -c "import json; print(json.load(open('/etc/vkvpn/config.json'))['server_private_key'])")

cat > /etc/wireguard/wg0.conf <<WG
[Interface]
PrivateKey = $WG_PRIV
Address = 10.66.66.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
WG
chmod 600 /etc/wireguard/wg0.conf

# Enable and start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0 2>/dev/null || systemctl restart wg-quick@wg0

# Check if binary exists
if [ ! -f /opt/vkvpn/server ]; then
  echo ""
  echo "NOTE: Server binary not found at /opt/vkvpn/server"
  echo "Build and copy it:"
  echo "  cd server && go build -ldflags '-s -w' -trimpath -o server ."
  echo "  scp server root@$SERVER_IP:/opt/vkvpn/server"
fi

# Create systemd service
cat > /etc/systemd/system/vkvpn.service <<SVC
[Unit]
Description=VKVPN Server
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/opt/vkvpn/server -config /etc/vkvpn/config.json -ip $SERVER_IP -web 0.0.0.0:8080 -dtls 0.0.0.0:56000 -wg-connect 127.0.0.1:51820
Restart=always
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/vkvpn /etc/wireguard

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable vkvpn

if [ -f /opt/vkvpn/server ]; then
  systemctl restart vkvpn
  echo "VKVPN service started!"
fi

# Open firewall ports
if command -v ufw &>/dev/null; then
  ufw allow 51820/udp   # WireGuard
  ufw allow 56000/udp   # DTLS
  ufw allow 8080/tcp    # Admin panel
  echo "Firewall ports opened"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Server IP:    $SERVER_IP"
echo "WireGuard:    port 51820/udp"
echo "DTLS:         port 56000/udp"
echo "Admin panel:  http://$SERVER_IP:8080/?token=$ADMIN_PASS"
echo ""
echo "Next steps:"
echo "1. Build server: cd server && go build -ldflags '-s -w' -trimpath -o server ."
echo "2. Copy to VPS:  scp server root@$SERVER_IP:/opt/vkvpn/server"
echo "3. Start:        systemctl start vkvpn"
echo "4. Open admin:   http://$SERVER_IP:8080/?token=$ADMIN_PASS"
echo "5. Add clients and scan QR codes on phones"
