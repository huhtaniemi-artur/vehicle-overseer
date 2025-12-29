#!/usr/bin/env bash
set -Eeuo pipefail

log() { printf '[srvcsetup] %s\n' "$*" >&2; }

trap 'rc=$?; log "ERROR (exit $rc) at line $LINENO: $BASH_COMMAND"; exit $rc' ERR

# This script is intended to be served by the backend at `/api/srvcsetup`.
# The backend replaces the __PLACEHOLDER__ values before returning it.

if [ "$(id -u)" -ne 0 ]; then
  log "run as root (use sudo)"
  exit 2
fi

BACKEND_BASE=__BACKEND_BASE__
VIN=__VIN__
TOKEN=__TOKEN__
REPORT_IFACE=__REPORT_IFACE__
ACTION_PORT=__ACTION_PORT__
LOG_PORT=__LOG_PORT__
PING_INTERVAL_S=__PING_INTERVAL_S__
INSTALL_ROOT=__INSTALL_ROOT__
ENV_DIR=__ENV_DIR__
SYSTEMD_DIR=/etc/systemd/system
BOOTSTRAP_DIR="$INSTALL_ROOT/bootstrap"

if ! command -v systemctl >/dev/null 2>&1; then
  log "systemctl not found (systemd required)"
  exit 2
fi
if ! command -v tar >/dev/null 2>&1; then
  log "tar not found"
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  log "python3 not found"
  exit 2
fi

log "backend=$BACKEND_BASE vin=$VIN reportIface=$REPORT_IFACE actionPort=$ACTION_PORT logPort=$LOG_PORT pingInterval=${PING_INTERVAL_S}s"
log "installRoot=$INSTALL_ROOT envDir=$ENV_DIR"

mkdir -p "$INSTALL_ROOT/releases" "$ENV_DIR" "$BOOTSTRAP_DIR"

FETCH() {
  local url="$1"
  log "fetch: $url"
  curl -fsSL "$url"
}

# Fetch templates/config from backend (script stays minimal).
mkdir -p "$SYSTEMD_DIR"

log "fetch device artifact key (overwrite $ENV_DIR/artifact.key)"
if [ -z "$TOKEN" ]; then
  log "missing bootstrap token; call /api/srvcsetup with ?vin=...&token=..."
  exit 3
fi
KEY_URL="$BACKEND_BASE/api/device/key?token=$TOKEN"
log "fetch: $KEY_URL"
KEY_RAW="$(curl -fsSL "$KEY_URL")"
DEVICE_UID="$(printf '%s' "$KEY_RAW" | awk 'NR==1 {print $1}')"
KEY_B64="$(printf '%s' "$KEY_RAW" | awk 'NR==2 {print $1}')"
if [ -z "$KEY_B64" ] || [ -z "$DEVICE_UID" ]; then
  log "failed to parse key response"
  exit 3
fi
umask 077
printf "%s\n" "$KEY_B64" >"$ENV_DIR/artifact.key"
log "wrote $ENV_DIR/artifact.key"
printf "%s\n" "$DEVICE_UID" >"$ENV_DIR/device.uid"
log "wrote $ENV_DIR/device.uid"

if [ ! -f "$ENV_DIR/device.env" ]; then
  log "write $ENV_DIR/device.env (new)"
  FETCH "$BACKEND_BASE/api/srvcsetup/files/device.env?vin=$VIN&reportIface=$REPORT_IFACE&actionPort=$ACTION_PORT&logPort=$LOG_PORT&pingIntervalS=$PING_INTERVAL_S" >"$ENV_DIR/device.env"
else
  log "keep existing $ENV_DIR/device.env"
fi

if [ ! -f "$ENV_DIR/updater.env" ]; then
  log "write $ENV_DIR/updater.env (new)"
  FETCH "$BACKEND_BASE/api/srvcsetup/files/updater.env" >"$ENV_DIR/updater.env"
else
  log "keep existing $ENV_DIR/updater.env"
fi


log "install systemd units"
log "skip unit install here (handled by updater)"

log "install bootstrap updater"
FETCH "$BACKEND_BASE/api/srvcsetup/files/vo_updater.py" >"$BOOTSTRAP_DIR/vo_updater.py"
chmod +x "$BOOTSTRAP_DIR/vo_updater.py"
ln -sfn "$BOOTSTRAP_DIR" "$INSTALL_ROOT/current"
log "set current -> $BOOTSTRAP_DIR"

if [ -t 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
  log "open editor to finalize config (device.env, updater.env)"
  if command -v nano >/dev/null 2>&1; then
    nano "$ENV_DIR/device.env" "$ENV_DIR/updater.env" </dev/tty >/dev/tty
  elif [ -n "${EDITOR:-}" ]; then
    "$EDITOR" "$ENV_DIR/device.env" "$ENV_DIR/updater.env" </dev/tty >/dev/tty
  else
    log "no editor available; edit $ENV_DIR/device.env then run:"
    log "  systemctl daemon-reload && systemctl enable --now vehicle-overseer-device.service vo-updater.timer"
    exit 0
  fi
else
  log "no interactive TTY; skip editor (edit $ENV_DIR/device.env manually if needed)"
fi

log "run updater (initial install)"
/usr/bin/python3 "$BOOTSTRAP_DIR/vo_updater.py" apply \
  --backend "$BACKEND_BASE" \
  --vin "$VIN" \
  --artifact-key-path "$ENV_DIR/artifact.key" \
  --device-uid-path "$ENV_DIR/device.uid"

log "ok"
