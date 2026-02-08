#!/bin/sh
set -eu

log() { printf '[updater-setup] %s\n' "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${VO_APP_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SYSTEMD_DIR=/etc/systemd/system

UPDATER_SERVICE_NAME=vehicle-overseer-updater.service
UPDATER_TIMER_NAME=vehicle-overseer-updater.timer

# Ensure updater.py is available at app root for direct execution.
if [ -f "$SCRIPT_DIR/updater.py" ]; then
  cp "$SCRIPT_DIR/updater.py" "$APP_DIR/updater.py"
  chmod 0755 "$APP_DIR/updater.py"
fi

NO_SYSTEMD=0
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
  NO_SYSTEMD=1
  log "systemd not running; will copy unit files but skip systemctl"
fi

src_dir=""
if [ -d "$APP_DIR/updater/systemd" ]; then
  src_dir="$APP_DIR/updater/systemd"
elif [ -d "$APP_DIR/systemd" ]; then
  src_dir="$APP_DIR/systemd"
fi

if [ -z "$src_dir" ]; then
  log "no updater systemd templates found"
  exit 0
fi

mkdir -p "$SYSTEMD_DIR"

if [ -f "$src_dir/updater.service" ]; then
  cp "$src_dir/updater.service" "$SYSTEMD_DIR/$UPDATER_SERVICE_NAME"
  chmod 0644 "$SYSTEMD_DIR/$UPDATER_SERVICE_NAME"
else
  log "warn: missing updater.service in $src_dir"
fi

if [ -f "$src_dir/updater.timer" ]; then
  cp "$src_dir/updater.timer" "$SYSTEMD_DIR/$UPDATER_TIMER_NAME"
  chmod 0644 "$SYSTEMD_DIR/$UPDATER_TIMER_NAME"
else
  log "warn: missing updater.timer in $src_dir"
fi

if [ "$NO_SYSTEMD" -eq 0 ]; then
  systemctl daemon-reload || log "warn: systemctl daemon-reload failed"
  systemctl enable --now "$UPDATER_TIMER_NAME" || log "warn: failed to enable $UPDATER_TIMER_NAME"
else
  log "systemd unavailable; unit files copied but not enabled"
fi

log "ok"
