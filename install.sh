#!/bin/bash
set -euo pipefail

DEST="/opt/mtproto-exporter"
SERVICE="mtproto-exporter.service"

echo "Installing MTProto MEKO Prometheus Exporter..."

# Устанавливаем conntrack-tools для per-IP статистики
if ! command -v conntrack &>/dev/null; then
    echo "Installing conntrack-tools..."
    apt-get update -qq && apt-get install -y -qq conntrack 2>/dev/null || \
    yum install -y -q conntrack-tools 2>/dev/null || \
    echo "Warning: conntrack-tools install failed — per-IP stats will use /proc fallback"
fi

mkdir -p "$DEST"
cp mtproto_exporter.py "$DEST/"
chmod +x "$DEST/mtproto_exporter.py"

cp "$SERVICE" /etc/systemd/system/

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

echo "Done. Service status:"
systemctl status "$SERVICE" --no-pager
echo ""
echo "Exporter running on :9095"
echo "Metrics: http://localhost:9095/metrics"
