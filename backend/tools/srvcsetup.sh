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

mkdir -p "$INSTALL_ROOT/releases" "$ENV_DIR"

FETCH() {
  local url="$1"
  log "fetch: $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  else
    wget -qO- "$url"
  fi
}

# Fetch templates/config from backend (script stays minimal).
mkdir -p "$SYSTEMD_DIR"

log "fetch device artifact key (overwrite $ENV_DIR/artifact.key)"
if [ -z "$TOKEN" ]; then
  log "missing bootstrap token; call /api/srvcsetup with ?vin=...&token=..."
  exit 3
fi
KEY_URL="$BACKEND_BASE/api/device/key?token=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$TOKEN")"
KEY_JSON="$(FETCH "$KEY_URL")"
KEY_B64="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["keyB64"])' "$KEY_JSON")"
DEVICE_UID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["deviceUid"])' "$KEY_JSON")"
umask 077
printf "%s\n" "$KEY_B64" >"$ENV_DIR/artifact.key"
log "wrote $ENV_DIR/artifact.key"
printf "%s\n" "$DEVICE_UID" >"$ENV_DIR/device.uid"
log "wrote $ENV_DIR/device.uid"

if [ ! -f "$ENV_DIR/device.env" ]; then
  log "write $ENV_DIR/device.env (new)"
  FETCH "$BACKEND_BASE/api/srvcsetup/files/device.env?vin=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$VIN")&reportIface=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$REPORT_IFACE")&actionPort=$ACTION_PORT&logPort=$LOG_PORT&pingIntervalS=$PING_INTERVAL_S" >"$ENV_DIR/device.env"
else
  log "keep existing $ENV_DIR/device.env"
fi

python3 - "$ENV_DIR/device.env" "$DEVICE_UID" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
uid = sys.argv[2]
lines = []
if path.exists():
    lines = path.read_text(encoding="utf-8").splitlines()
lines = [line for line in lines if not line.startswith("VO_DEVICE_UID=")]
lines.append(f"VO_DEVICE_UID={uid}")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

if [ ! -f "$ENV_DIR/updater.env" ]; then
  log "write $ENV_DIR/updater.env (new)"
  FETCH "$BACKEND_BASE/api/srvcsetup/files/updater.env" >"$ENV_DIR/updater.env"
else
  log "keep existing $ENV_DIR/updater.env"
fi

log "install systemd units"
FETCH "$BACKEND_BASE/api/srvcsetup/files/vehicle-overseer-device.service" >"$SYSTEMD_DIR/vehicle-overseer-device.service"
FETCH "$BACKEND_BASE/api/srvcsetup/files/vo-updater.service" >"$SYSTEMD_DIR/vo-updater.service"
FETCH "$BACKEND_BASE/api/srvcsetup/files/vo-updater.timer" >"$SYSTEMD_DIR/vo-updater.timer"

# Fetch manifest + artifact (SHA256 verified); install into releases/<version> and point current -> it.
MANIFEST_URL="$BACKEND_BASE/api/device/manifest?vin=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$VIN")"
log "get manifest"
MANIFEST_JSON="$(FETCH "$MANIFEST_URL")"

VERSION="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["version"])' "$MANIFEST_JSON")"
ART_URL="$(python3 -c 'import json,sys; m=json.loads(sys.argv[1]); print(m["artifact"]["url"])' "$MANIFEST_JSON")"
ART_SHA="$(python3 -c 'import json,sys; m=json.loads(sys.argv[1]); print(m["artifact"]["sha256"])' "$MANIFEST_JSON")"
FULL_ART_URL="$BACKEND_BASE$ART_URL"
log "manifest version=$VERSION"

TMPDIR="$(mktemp -d)"
cleanup(){ rm -rf "$TMPDIR" || true; }
trap cleanup EXIT

log "download artifact"
FETCH "$FULL_ART_URL" >"$TMPDIR/artifact.tar.gz"

log "verify artifact sha256"
PY_GOT_SHA="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMPDIR/artifact.tar.gz")"
if [ "$PY_GOT_SHA" != "$ART_SHA" ]; then
  log "artifact sha256 mismatch"
  exit 3
fi

REL_DIR="$INSTALL_ROOT/releases/$VERSION"
log "install release to $REL_DIR"
rm -rf "$REL_DIR"
mkdir -p "$REL_DIR"
tar -xzf "$TMPDIR/artifact.tar.gz" -C "$REL_DIR"
if [ ! -f "$REL_DIR/VERSION" ]; then
  printf "%s\n" "$VERSION" >"$REL_DIR/VERSION"
fi
ln -sfn "$REL_DIR" "$INSTALL_ROOT/current"
log "set current -> $REL_DIR"

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

log "systemd daemon-reload"
systemctl daemon-reload
log "enable+start: vehicle-overseer-device.service"
log "enable+start: vo-updater.timer"
systemctl enable --now vehicle-overseer-device.service vo-updater.timer

log "ok"
