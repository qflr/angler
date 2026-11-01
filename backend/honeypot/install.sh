#!/usr/bin/env bash
# Install the Angler decoy sensor on a fresh Ubuntu/Debian VM as a locked-down systemd service.
#   sudo INGEST_KEY=... ANGLER_API=https://angler-api.onrender.com bash install.sh
# Expects sensor.py next to this script. Re-running upgrades in place.
set -euo pipefail

: "${INGEST_KEY:?set INGEST_KEY}"
ANGLER_API="${ANGLER_API:-https://angler-api.onrender.com}"
HERE="$(cd "$(dirname "$0")" && pwd)"

apt-get update -qq
apt-get install -y -qq python3 openssl >/dev/null

id angler &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin angler
install -d -o root -g root -m 755 /opt/angler
install -o root -g root -m 644 "$HERE/sensor.py" /opt/angler/sensor.py
install -d -o angler -g angler -m 700 /var/lib/angler
install -d -o root -g angler -m 750 /etc/angler

# Self-signed cert so :443 answers TLS like a real box (scanners don't validate it).
if [ ! -f /etc/angler/tls.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=localhost" \
    -keyout /etc/angler/tls.key -out /etc/angler/tls.crt 2>/dev/null
  chown root:angler /etc/angler/tls.key /etc/angler/tls.crt
  chmod 640 /etc/angler/tls.key
fi

umask 077
cat > /etc/angler/sensor.env <<ENV
ANGLER_API=$ANGLER_API
INGEST_KEY=$INGEST_KEY
ANGLER_SPOOL=/var/lib/angler/spool.jsonl
ENV
chown root:angler /etc/angler/sensor.env
chmod 640 /etc/angler/sensor.env

cat > /etc/systemd/system/angler-sensor.service <<'UNIT'
[Unit]
Description=Angler decoy sensor (logs requests, executes nothing)
After=network-online.target
Wants=network-online.target

[Service]
User=angler
Group=angler
EnvironmentFile=/etc/angler/sensor.env
ExecStart=/usr/bin/python3 /opt/angler/sensor.py --port 80 --tls-port 443 --cert /etc/angler/tls.crt --key /etc/angler/tls.key
Restart=always
RestartSec=2
# Bind 80/443 without root, and nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=/var/lib/angler
MemoryMax=256M
TasksMax=200

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now angler-sensor
systemctl restart angler-sensor
sleep 2
systemctl --no-pager --lines=5 status angler-sensor
