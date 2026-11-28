#!/bin/bash
# PS5 Research VPS Setup Script
# Run this on a fresh Ubuntu VPS (Oracle Cloud Free Tier or similar)
# Usage: bash vps_setup.sh YOUR_HOME_IP
#
# This sets up:
# 1. DNS server (dnsmasq) - hijacks manuals.playstation.net to this VPS
# 2. HTTPS server (nginx) - serves probes only to PS5 v14+ browsers
# 3. Let's Encrypt cert for HTTPS
# 4. Beacon collection logging

set -e

is_ipv4() {
  local ip="$1" octet
  local -a octets
  IFS=. read -r -a octets <<< "$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
  done
}

HOME_IP="${1:-REPLACE_ME}"
VPS_IP=$(curl -fsS --max-time 10 https://ifconfig.me)
if ! is_ipv4 "$VPS_IP"; then
  echo "Could not determine this VPS's public IPv4 (got: '${VPS_IP:-empty}')." >&2
  echo "Fix connectivity to ifconfig.me or set VPS_IP manually, then re-run." >&2
  exit 1
fi

echo "=== PS5 Research VPS Setup ==="
echo "VPS IP: $VPS_IP"
echo "Home IP (allowed for 13.60 testing): $HOME_IP"
echo ""

# Install packages
echo "[1/5] Installing packages..."
sudo apt update -y
sudo apt install -y nginx dnsmasq certbot python3-certbot-nginx

# Configure dnsmasq
echo "[2/5] Configuring DNS..."
sudo systemctl stop systemd-resolved 2>/dev/null || true
sudo systemctl disable systemd-resolved 2>/dev/null || true
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

sudo tee /etc/dnsmasq.conf > /dev/null << EOF
listen-address=0.0.0.0
no-resolv
server=8.8.8.8
server=8.8.4.4

# Hijack PS5 User Guide to this server
address=/manuals.playstation.net/$VPS_IP

# Block PS5 firmware updates
address=/fus01.ps5.update.playstation.net/#
address=/fus02.ps5.update.playstation.net/#
address=/update.playstation.net/#
address=/a0.ww.np.dl.playstation.net/#
address=/gs-sec.ww.np.dl.playstation.net/#

# Everything else resolves normally via Google DNS
EOF

sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq
echo "  DNS: manuals.playstation.net -> $VPS_IP"

# Set up web root
echo "[3/5] Setting up web content..."
sudo install -d -o "$USER" -g "$USER" -m 755 /var/www/ps5research
# Probes will be deployed here via SCP

# Configure nginx
echo "[4/5] Configuring nginx..."
sudo tee /etc/nginx/sites-available/ps5research > /dev/null << 'NGINXEOF'
server {
    listen 80;
    listen 443 ssl;
    server_name manuals.playstation.net;

    # SSL certs (certbot fills these in)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # PS5 v14+ verification via User-Agent
    set $ps5ok 0;
    if ($http_user_agent ~* "PlayStation 5/(1[4-9]|[2-9][0-9])\.") { set $ps5ok 1; }
NGINXEOF

# Add home IP allowance
echo "    if (\$remote_addr = \"$HOME_IP\") { set \$ps5ok 1; }" | sudo tee -a /etc/nginx/sites-available/ps5research > /dev/null

sudo tee -a /etc/nginx/sites-available/ps5research > /dev/null << 'NGINXEOF'
    if ($uri ~ ^/\.well-known/acme-challenge/) { set $ps5ok 1; }
    if ($ps5ok = 0) { return 403 "PS5 firmware 14.00+ required."; }

    add_header X-Frame-Options "DENY" always;
    add_header Cache-Control "no-store, no-cache" always;

    root /var/www/ps5research;

    location /document/gb/ps5/ { try_files /launcher.html =404; }
    location /document/gb/ps5/probe-modules.html { try_files /probe-modules.html =404; }

    location /beacon/ {
        access_log /var/log/nginx/ps5_beacons.log;
        add_header Access-Control-Allow-Origin "*" always;
        return 200 "ok";
    }

    location /probes/ { try_files $uri =404; }

    location / { return 403; }
}
NGINXEOF

sudo ln -sf /etc/nginx/sites-available/ps5research /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable nginx

echo "[5/5] Opening firewall ports..."
sudo iptables -I INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || true

echo ""
echo "=== SETUP COMPLETE ==="
echo ""
echo "VPS IP: $VPS_IP"
echo "DNS: manuals.playstation.net -> $VPS_IP"
echo ""
echo "Next steps:"
echo "  1. Deploy probes: scp probes/phase13_webkit/data-gather/*.html user@$VPS_IP:/var/www/ps5research/"
echo "  2. Tell testers: Set PS5 DNS to $VPS_IP"
echo "  3. Check beacons: tail -f /var/log/nginx/ps5_beacons.log"
echo ""
echo "Note: HTTPS uses a self-signed cert. PS5 will show a cert warning."
echo "Testers click 'Yes' to accept. For a proper cert, run:"
echo "  sudo certbot --nginx -d manuals.playstation.net --cert-name ps5research"
echo "(requires the domain to point to this IP, which it won't for DNS hijack)"
