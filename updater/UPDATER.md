# Updater (prototype)

This repo contains a pull-based updater design intended for Linux devices running systemd.

## Device-side pieces

- Service implementation: `device-service/service.py`
- Updater: `updater/updater.py`
- Systemd templates: `updater/systemd/`

The recommended on-device layout is:

- `/opt/vehicle-overseer/app/` (active app files, including `service.py` and `update.sh`)
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

- `update.sh` (required)
- `service.py`
- `VERSION` (string matching manifest version)
- Optional: `updater.py` (allows the updater to self-update)
- Optional: `updater/systemd/updater.service`, `updater/systemd/updater.timer` (installed as `vehicle-overseer-updater.*` by `update.sh`)
- `updater/updater-setup.sh` (installs/enables updater systemd units)
- `device-service/service-setup.sh` + `device-service/systemd/vehicle-overseer.service` (device service is installed as `vehicle-overseer.service`)

## How artifacts are provided (current backend)

Artifacts are stored by content hash (artifact id) under:

- `backend/data/artifacts/<sha256>`

Versions are tags stored in SQLite (`versions.version`) mapped to a single package artifact (`versions.artifact_id`).

Artifact management is split into two independent operations:

- `make`: create a `.tar.gz` artifact from a directory (or accept an existing tarball). This does not touch SQLite.
- `import`: publish that artifact into the backend runtime state (copy bytes into `backend/data/artifacts/<sha256>` and update SQLite `artifacts` + `versions`).

Local (developer machine): make artifacts

- Shorthand (implies `make`):
  - `node updater/artifacts.js ./release-dir --version v0.1.0 --out ./artifact_v0.1.0.tar.gz`
- Explicit:
  - `node updater/artifacts.js make ./release-dir --version v0.1.0 --out ./artifact_v0.1.0.tar.gz`

Local (developer machine): import into your local backend workspace

- `node updater/artifacts.js import ./artifact_v0.1.0.tar.gz --version v0.1.0`


Notes:
- When updater `systemd/` units are missing in the release dir, `make` copies them from `updater/systemd/`.
- When `update.sh` is missing, `make` injects a default script (built-in to `updater/artifacts.js`).
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
- The updater swaps `app/` to `app.bak/`, installs the new app, runs `update.sh`, then removes `app.bak/` on success.
- Device can report per-device ports in `POST /api/ping` (`data.actionPort`, `data.logPort`); backend prefers these over global defaults when present.
- Service version info is reported in `POST /api/ping` as `data.version` (e.g. `serviceVersion`).
