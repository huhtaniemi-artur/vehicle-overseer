#!/bin/sh
set -eu

log() { printf '[device-setup] %s\n' "$*" >&2; }

APP_DIR="${VO_APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
SYSTEMD_DIR=/etc/systemd/system
UNIT_SRC="$APP_DIR/device-service/systemd/vehicle-overseer.service"
UNIT_DST="$SYSTEMD_DIR/vehicle-overseer.service"

if ! command -v systemctl >/dev/null 2>&1; then
  log "systemctl not found (systemd required)"
  exit 2
fi

mkdir -p "$SYSTEMD_DIR"

if [ ! -f "$UNIT_SRC" ]; then
  log "missing unit template: $UNIT_SRC"
  exit 2
fi

log "install unit: $UNIT_DST"
cp "$UNIT_SRC" "$UNIT_DST"
chmod 0644 "$UNIT_DST"

systemctl daemon-reload
systemctl enable --now vehicle-overseer.service

log "ok"
