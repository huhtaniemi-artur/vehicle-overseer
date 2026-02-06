Backend scaffold
================

This is a Node.js backend for the web switcher concept. Implement the API/WebSocket/log streaming behavior per `architecture.txt` and `architecture.md`.

Setup
1) Create `config.json` (optional). If missing, the backend uses internal defaults.
2) Install deps: `npm install`.
3) Run: `npm start` (starts HTTP + WebSocket server; see endpoints below).

Example config.json
```json
{
	"dbPath": "./data/vehicle_overseer.sqlite",
	"httpHost": "0.0.0.0",
	"httpPort": 3100,
	"defaultSshUser": "user",
	"defaultServiceName": "usrapp.service",
	"defaultMqttKey": "mqttServerIp",
	"deviceActionPort": 9000,
	"deviceLogPort": 9100,
	"devicePingIntervalS": 10,
	"ipList": [
		"tcp://10.99.2.10:11883",
		"tcp://10.99.12.10:11883",
		"tcp://10.102.1.10:11883"
	]
}
```

SEA binary build (official Node “Single Executable Application”)
1) Build on the target OS/arch (Node 20+ required for build time):
	- `npm install`
	- `npm run build:sea`
2) Deploy by copying `backend/dist/` to the target machine.
	- Run: `./vehicle-overseer-backend` from inside that folder.
	- Optional: create `config.json` next to the binary (otherwise it uses internal defaults).
	- Keep `dist/schema.sql`, `dist/tools/`, and `dist/sql-wasm.wasm` alongside the executable (used at runtime).

Artifacts
---------
Artifact management is split into two operations:
- `make`: create a `.tar.gz` artifact from a directory (or accept an existing `.tar.gz`). This does not touch SQLite.
- `import`: copy artifact bytes into the backend’s runtime `data/` directory and update SQLite tables (`artifacts`, `versions`).

Local (developer machine): make artifacts
- Shorthand (path implies `make`): `node updater/artifacts.js ./release-dir --version v0.1.0 --out ./artifact_v0.1.0.tar.gz`
- Explicit: `node updater/artifacts.js make ./release-dir --version v0.1.0 --out ./artifact_v0.1.0.tar.gz`
- Combined (make + import into your local backend workspace): `node updater/artifacts.js ./release-dir --version v0.1.0 --out ./artifact_v0.1.0.tar.gz --import`

Local (developer machine): import into your local backend workspace
- From repo root: `node updater/artifacts.js import ./artifact_v0.1.0.tar.gz --version v0.1.0`
- Shortcut (from `backend/`): `npm run artifacts -- import ../artifact_v0.1.0.tar.gz --version v0.1.0`

Notes:
- If the server is already running, the backend reloads the SQLite DB on subsequent HTTP requests when the DB file mtime changes.

Runtime root (SEA + dev)
- The backend resolves paths (config/data/schema/tools) relative to `process.cwd()`.
- For systemd, set `WorkingDirectory=/path/to/dist` (recommended).

Notes
- SEA produces a native executable by copying your current `node` binary and injecting an app blob.
- The backend will create `./data/` next to the executable on first run.

Key files
- `config.json`: Optional runtime config (if missing, backend uses internal defaults).
- `schema.sql`: Tables for update artifacts/versions, per-device update targets, device keys, and bootstrap tokens.
- `src/index.js`: Minimal functional server with HTTP endpoints, shared WebSocket for UI, per-device log WebSocket proxy, SQLite (sql.js/WASM) wiring for update metadata, and per-action backend→device connection stub (TCP in dev; later real device integration).
- `../device-service/simulator.py`: Python simulator that acts like a device/service (POST pings with uid + label, TCP action endpoint, TCP log stream).

Endpoints
- HTTP: `GET /api/config`, `GET /api/entries`, `POST /api/ping`, `POST /api/action/select`, `GET /api/health`
- WS: `ws://host:port/ws` (UI updates), `ws://host:port/logs?uid=UID` (per-device log proxy)

UI
- `GET /` serves `index.html` when available (so the backend can run standalone without Python).
