#!/bin/sh
set -eu

log() { printf '[update.sh] %s\n' "$*" >&2; }

ACTION="${1:-}"
if [ -z "$ACTION" ]; then
  log "usage: update.sh install|remove"
  exit 2
fi

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_ROOT="${VO_INSTALL_ROOT:-$(cd "$APP_DIR/.." && pwd)}"
SYSTEMD_DIR=/etc/systemd/system

if [ "$ACTION" = "install" ]; then
  mkdir -p "$SYSTEMD_DIR"
  if [ -d "$APP_DIR/systemd" ]; then
    log "install systemd units"
    for unit in "$APP_DIR"/systemd/*.service "$APP_DIR"/systemd/*.timer; do
      [ -f "$unit" ] || continue
      dst="$SYSTEMD_DIR/$(basename "$unit")"
      cp "$unit" "$dst"
      chmod 0644 "$dst"
    done
  else
    log "no systemd units to install"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || log "warn: systemctl daemon-reload failed"
    systemctl restart vehicle-overseer-device.service || log "warn: failed to restart vehicle-overseer-device.service"
    systemctl enable --now vo-updater.timer || log "warn: failed to enable vo-updater.timer"
  else
    log "warn: systemctl not found (skip service enable)"
  fi
  exit 0
fi

if [ "$ACTION" = "remove" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now vehicle-overseer-device.service || log "warn: failed to disable vehicle-overseer-device.service"
  else
    log "warn: systemctl not found (skip service disable)"
  fi
  rm -f "$SYSTEMD_DIR/vehicle-overseer-device.service"
  exit 0
fi

log "unknown action: $ACTION"
exit 2
