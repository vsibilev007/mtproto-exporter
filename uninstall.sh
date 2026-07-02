#!/bin/bash
set -euo pipefail

echo "Stopping MTProto MEKO Prometheus Exporter..."
systemctl stop mtproto-exporter.service 2>/dev/null || true
systemctl disable mtproto-exporter.service 2>/dev/null || true

rm -f /etc/systemd/system/mtproto-exporter.service
rm -rf /opt/mtproto-exporter

systemctl daemon-reload

echo "Done. Exporter removed."
