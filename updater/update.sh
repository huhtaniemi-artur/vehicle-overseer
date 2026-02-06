#!/bin/sh
set -eu

log() { printf '[update.sh] %s\n' "$*" >&2; }

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_ROOT="${VO_INSTALL_ROOT:-$(cd "$APP_DIR/.." && pwd)}"
SYSTEMD_DIR=/etc/systemd/system

UPDATER_SERVICE_NAME=vehicle-overseer-updater.service
UPDATER_TIMER_NAME=vehicle-overseer-updater.timer

install_updater_units() {
  src_dir=""
  if [ -d "$APP_DIR/updater/systemd" ]; then
    src_dir="$APP_DIR/updater/systemd"
  elif [ -d "$APP_DIR/systemd" ]; then
    src_dir="$APP_DIR/systemd"
  fi

  if [ -z "$src_dir" ]; then
    log "no updater systemd templates found"
    return 0
  fi

  mkdir -p "$SYSTEMD_DIR"
  if [ -f "$src_dir/updater.service" ]; then
    cp "$src_dir/updater.service" "$SYSTEMD_DIR/$UPDATER_SERVICE_NAME"
    chmod 0644 "$SYSTEMD_DIR/$UPDATER_SERVICE_NAME"
  fi
  if [ -f "$src_dir/updater.timer" ]; then
    cp "$src_dir/updater.timer" "$SYSTEMD_DIR/$UPDATER_TIMER_NAME"
    chmod 0644 "$SYSTEMD_DIR/$UPDATER_TIMER_NAME"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || log "warn: systemctl daemon-reload failed"
    systemctl enable --now "$UPDATER_TIMER_NAME" || log "warn: failed to enable $UPDATER_TIMER_NAME"
  else
    log "warn: systemctl not found (skip service enable)"
  fi
}

run_device_setup() {
  setup="$APP_DIR/device-service/setup.sh"
  if [ ! -f "$setup" ]; then
    log "no device-service setup script found"
    return 0
  fi
  if [ -x "$setup" ]; then
    "$setup"
  else
    sh "$setup"
  fi
}

run_updater_setup() {
  # Optional user-provided commands for custom scenarios.
  # If present in the artifact, it runs as part of `install`.
  setup="$APP_DIR/updater/setup.sh"
  if [ ! -f "$setup" ]; then
    return 0
  fi
  log "run updater setup: $setup"
  if [ -x "$setup" ]; then
    "$setup"
  else
    sh "$setup"
  fi
}


install_updater_units
run_updater_setup
run_device_setup
exit 0
