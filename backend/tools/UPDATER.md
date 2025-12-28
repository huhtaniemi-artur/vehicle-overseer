# Updater (prototype)

This repo contains a pull-based updater design intended for Linux devices running systemd.

## Device-side pieces

- Service implementation: `backend/tools/device_service.py`
- Updater: `backend/tools/vo_updater.py`
- Systemd templates: `backend/tools/systemd/`

The recommended on-device layout is:

- `/opt/vehicle-overseer-device/releases/<version>/...`
- `/opt/vehicle-overseer-device/current -> releases/<version>` (symlink)
- `/etc/vehicle-overseer/device.env` (device + backend settings)
- `/etc/vehicle-overseer/updater.env` (optional updater settings)

## Backend endpoints

- `GET /api/device/manifest?vin=VIN`
- `GET /api/device/artifacts/<artifact-id>`
- `GET /api/device/key?token=...` (setup-time key provisioning; token required)
- `POST /api/bootstrap-token` (localhost-only; create a one-time or dev token)

## Artifact format

The updater expects a `.tar.gz` with files at the archive root, e.g.:

- `device_service.py`
- `vo_updater.py`
- `VERSION` (string matching manifest version)

## How artifacts are provided (current backend)

Artifacts are stored by content hash (artifact id) under:

- `backend/data/artifacts/<sha256>`

Versions are tags stored in SQLite (`versions.version`) mapped to a single package artifact (`versions.artifact_id`).

Import a new version on the backend with:

- `node backend/tools/import_version.js --version v0.1.0 --file ./path/to/vehicle-overseer-device_v0.1.0.tar.gz`
- or build a bundle from a directory:
  - `node backend/tools/import_version.js --version v0.1.0 --dir ./release-dir`

If no artifacts exist, `GET /api/device/manifest` returns `404`.

## Notes

- Artifact integrity is checked by SHA256.
- Manifest authentication is optional via RSA signatures:
  - Backend signs using `updateSigningKeyPath` (private key, PEM).
  - Device verifies using `VO_UPDATE_PUBKEY_PATH` (public key, PEM).
- Optional in-transfer encryption:
  - Setup fetches a per-device base64 key from `GET /api/device/key?token=...` and stores it as `/etc/vehicle-overseer/artifact.key`.
  - The same response provides `deviceUid`, stored as `/etc/vehicle-overseer/device.uid` and exported as `VO_DEVICE_UID`.
  - Token creation: use `POST /api/bootstrap-token` (localhost only) to mint a token, then call `/api/srvcsetup?vin=...&token=...`.
  - Optional: mint a token explicitly from the backend (localhost only):
    - `curl -sS -X POST http://127.0.0.1:3100/api/bootstrap-token -H 'Content-Type: application/json' -d '{"kind":"dev"}'`
  - The updater uses `VO_ARTIFACT_KEY_PATH` and requests encrypted downloads by adding `?uid=DEVICE_UID` to the artifact URL; backend responds with `X-VO-Enc: aes-256-ctr` + `X-VO-Iv: ...`.
- Device can report per-device ports in `POST /api/ping` (`data.actionPort`, `data.logPort`); backend prefers these over global defaults when present.
- Service version info is reported in `POST /api/ping` as `data.version` (e.g. `serviceVersion`, `buildId`, `updaterVersion`).
