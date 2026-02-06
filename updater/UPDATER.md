# Updater (prototype)

This repo contains a pull-based updater design intended for Linux devices running systemd.

## Device-side pieces

- Service implementation: `device-service/device_service.py`
- Updater: `updater/updater.py`
- Systemd templates: `updater/systemd/`

The recommended on-device layout is:

- `/opt/vehicle-overseer/app/` (active app files, including `device_service.py` and `update.sh`)
- `/opt/vehicle-overseer/app.bak/` (previous app during update, removed after success)
- `/opt/vehicle-overseer/updater.py` (updater lives outside app)
- `/etc/vehicle-overseer/device.env` (device + backend settings)
- `/etc/vehicle-overseer/updater.env` (optional updater settings)

## Backend endpoints

- `GET /api/device/manifest?uid=DEVICE_UID`
- `GET /api/device/artifacts/<artifact-id>`
- `GET /api/device/key?token=...` (setup-time key provisioning; token required)
- `POST /api/bootstrap-token` (localhost-only; create a one-time or dev token)
- `GET /api/srvcsetup?label=...&token=...` (returns a bootstrap shell script)

## Artifact format

The updater expects a `.tar.gz` with files at the archive root, e.g.:

- `update.sh` (required; invoked as `update.sh install` and `update.sh remove`)
- `device_service.py`
- `VERSION` (string matching manifest version)
- Optional: `updater.py` (allows the updater to self-update)
- Optional: `systemd/device.service`, `systemd/updater.service`, `systemd/updater.timer` (installed as `vehicle-overseer-*.service|*.timer` by `update.sh`)

## How artifacts are provided (current backend)

Artifacts are stored by content hash (artifact id) under:

- `backend/data/artifacts/<sha256>`

Versions are tags stored in SQLite (`versions.version`) mapped to a single package artifact (`versions.artifact_id`).

Import a new version on the backend with:

- `node backend/tools/import_version.js --version v0.1.0 --file ./path/to/vehicle-overseer-device_v0.1.0.tar.gz`
- or build a bundle from a directory:
  - `node backend/tools/import_version.js --version v0.1.0 --dir ./release-dir`
Notes:
- When `systemd/` units or `update.sh` are missing in the release dir, `make` copies them from `updater/`.
- If no artifacts exist, `GET /api/device/manifest` returns `404`.

If no artifacts exist, `GET /api/device/manifest` returns `404`.

## Notes

- Artifact integrity is checked by SHA256.
- In-transfer encryption (always enabled):
  - Setup fetches a per-device base64 key from `GET /api/device/key?token=...`.
  - Response format is plain text: first line `deviceUid`, second line `keyB64`.
- Token creation: use `POST /api/bootstrap-token` (localhost only) to mint a token, then call `/api/srvcsetup?label=...&token=...`.
  - Example:
    - `curl -sS -X POST http://127.0.0.1:3100/api/bootstrap-token -H 'Content-Type: application/json' -d '{"kind":"dev"}'`
- The updater requires `VO_ARTIFACT_KEY_PATH` and requests encrypted downloads by adding `?uid=DEVICE_UID` to the artifact URL; backend responds with `X-VO-Enc: aes-256-ctr` + `X-VO-Iv: ...`.
- Device UID can be provided via `VO_DEVICE_UID` or a file at `/etc/vehicle-overseer/device.uid` (override with `VO_DEVICE_UID_PATH`).
- The updater swaps `app/` to `app.bak/`, installs the new app, runs `update.sh install`, then removes `app.bak/` on success.
- `updater.py remove` runs `update.sh remove`, disables/removes updater units, and deletes `app/` + `app.bak/`.
- Device can report per-device ports in `POST /api/ping` (`data.actionPort`, `data.logPort`); backend prefers these over global defaults when present.
- Service version info is reported in `POST /api/ping` as `data.version` (e.g. `serviceVersion`).
