Backend scaffold
================

This is a Node.js backend for the web switcher concept. Implement the API/WebSocket/log streaming behavior per `architecture.txt` and `architecture.md`.

Setup
1) Copy config: `cp config.example.json config.json` and adjust paths/ports/commands/users/IP list.
2) Install deps: `npm install`.
3) Run: `npm start` (starts HTTP + WebSocket server; see endpoints below).

Key files
- `config.example.json`: Defaults for service name, MQTT key, IP list, DB path, plus `deviceActionPort`/`deviceLogPort` for per-device action/log TCP endpoints (host = device `ip-address`).
- `schema.sql`: Tables for update artifacts/versions, per-device update targets, device keys, and bootstrap tokens.
- `src/index.js`: Minimal functional server with HTTP endpoints, shared WebSocket for UI, per-vehicle log WebSocket proxy, SQLite (sql.js/WASM) wiring for update metadata, and per-action backend→device connection stub (TCP in dev; later real device integration).
- `backend/tools/simulator.py`: Python simulator that acts like a device/service (POST pings, TCP action endpoint, TCP log stream).

Endpoints
- HTTP: `GET /api/config`, `GET /api/entries`, `POST /api/ping`, `POST /api/action/select`, `GET /api/health`
- WS: `ws://host:port/ws` (UI updates), `ws://host:port/logs?vin=VIN` (per-vehicle log proxy)
