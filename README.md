Vehicle Overseer (remote device manager small webUI)
==================================

Minimal scaffold for the web-based IP switcher/monitor described in the concept doc in the repo root. See `architecture.txt` and `architecture.md` for the current architecture narrative and diagram.

Components
- Backend (`backend/`): Node.js server that receives POST pings, pushes UI updates via WebSocket, starts per-action backend→device connections (stubbed via TCP in dev), and proxies per-vehicle logs from the device/service. SQLite stores update artifacts/versions, per-device update targets, device keys, and bootstrap tokens.
- Frontend (`frontend/`): Static app that connects to backend `/ws`, renders entries, lets you pick IPs (with confirm), and shows log overlay streams.
- Database (`backend/schema.sql`): SQLite schema for update artifacts/versions, per-device update targets, device keys, and bootstrap tokens.
- Docs: concept doc in repo root, `architecture.txt`, `architecture.md`.
 - Simulator (`backend/tools/simulator.py`): Python device/service simulator for updates + action endpoint + log stream.

Quick start
1) Requirements: Node.js 18+; SQLite CLI (`sqlite3`).
2) Configure backend: `cp backend/config.example.json backend/config.json` and adjust ports/users/service names/IP list.
   - `deviceActionPort` / `deviceLogPort` define the per-device TCP ports the backend will connect to for actions/logs (host = the device `ip-address` reported via `/api/ping`).
3) Initialize DB: `mkdir -p backend/data` then `sqlite3 backend/data/vehicle_overseer.sqlite < backend/schema.sql`.
4) Install backend deps: `cd backend && npm install`.
5) Run backend: `npm start` (HTTP + WS on the configured port; provides `/api/ping` and WebSocket `/ws` plus per-vehicle `/logs`).
6) Serve frontend: `cd frontend && python -m http.server 8088` (or any static server). In the UI set the backend base (e.g., `http://localhost:3100`) via the input, or open with `?backend=http://localhost:3100`.

Notes
- Per-vehicle commands should be stored outside the repo.
- The current implementation uses a simulator for device action/log endpoints; replace with real device integration per the architecture docs.
