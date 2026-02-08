Vehicle Overseer (remote device manager small webUI)
==================================

Minimal scaffold for the web-based IP switcher/monitor described in the concept doc in the repo root. See `architecture.txt` and `architecture.md` for the current architecture narrative and diagram.

Components
- Backend (`backend/`): Node.js server that receives POST pings, pushes UI updates via WebSocket, starts per-action backend→device connections (stubbed via TCP in dev), and proxies per-vehicle logs from the device/service. SQLite stores update artifacts/versions, per-device update targets, device keys, and bootstrap tokens.
- Frontend (`frontend/`): Static app that connects to backend `/ws`, renders entries, lets you pick IPs (with confirm), and shows log overlay streams.
- Database (`backend/schema.sql`): SQLite schema for update artifacts/versions, per-device update targets, device keys, and bootstrap tokens.
- Docs: concept doc in repo root, `architecture.txt`, `architecture.md`.
- Simulator (`device-service/simulator.py`): Python device/service simulator for updates + action endpoint + log stream.

Quick start
1) Requirements: Node.js 18+; SQLite CLI (`sqlite3`).
2) Configure backend: create `backend/config.json` (optional). If missing, the backend uses internal defaults.
   - `deviceActionPort` / `deviceLogPort` define the per-device TCP ports the backend will connect to for actions/logs (host = the device `ip-address` reported via `/api/ping`).
3) Initialize DB: `mkdir -p backend/data` then `sqlite3 backend/data/vehicle_overseer.sqlite < backend/schema.sql`.
4) Install backend deps: `cd backend && npm install`.
5) Run backend: `npm start` (HTTP + WS on the configured port; provides `/api/ping` and WebSocket `/ws` plus per-vehicle `/logs`).
6) UI:
   - Easiest: open `http://localhost:3100/` (backend serves `index.html`).
   - Or serve frontend separately: `cd frontend && python -m http.server 8088` (or any static server). In the UI set the backend base (e.g., `http://localhost:3100`) via the input, or open with `?backend=http://localhost:3100`.

Notes
- Per-vehicle commands should be stored outside the repo.

Artifacts
- Build (from backend/): `node ../updater/artifacts.js <version> --module <path> [--module <path>]...` writes a hash-named artifact (outer tar with `hash` + `data`) into `data/artifacts/<hash>` and prints the hash.
- Sync DB: `node src/index.js artifacts refresh` (adds/removes artifacts on disk and updates versions/latest in SQLite).
- Server (SEA dist): copy the hash-named file into `data/artifacts/` then run `./vehicle-overseer-backend artifacts refresh`, or import directly: `./vehicle-overseer-backend artifacts import /path/to/<artifact-hash>`.
