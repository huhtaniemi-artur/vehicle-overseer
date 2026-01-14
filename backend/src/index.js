#!/usr/bin/env node

// Minimal functional backend: HTTP API + WebSockets, per-action device connections, and log proxying.
// Uses sql.js (WASM SQLite) for portability; no native builds required.

import http from 'http';
import fs from 'fs';
import path from 'path';
import url from 'url';
import net from 'net';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import initSqlJs from 'sql.js';
import { WebSocketServer } from 'ws';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
// Runtime root directory for config/data/assets.
// - Rely on process.cwd() so systemd can control it via WorkingDirectory=.
// - Fallback to repo backend/ directory for local dev.
const devRootDir = path.resolve(__dirname, '..');
const rootDir = process.cwd() || devRootDir;

async function main() {
  const defaultConfig = {
    dbPath: './data/vehicle_overseer.sqlite',
    httpHost: '0.0.0.0',
    httpPort: 3100,
    defaultSshUser: null,
    defaultServiceName: null,
    defaultMqttKey: 'mqttServerIp',
    deviceActionPort: 9000,
    deviceLogPort: 9100,
    devicePingIntervalS: 10,
    ipList: []
  };

  // Load config (config.json if present; otherwise internal defaults)
  const loadConfig = () => {
    const preferred = path.join(rootDir, 'config.json');
    if (!fs.existsSync(preferred)) return { ...defaultConfig };
    const parsed = JSON.parse(fs.readFileSync(preferred, 'utf-8'));
    return { ...defaultConfig, ...parsed };
  };

  const config = loadConfig();

  // Ensure data directory
  const dataDir = path.resolve(rootDir, 'data');
  fs.mkdirSync(dataDir, { recursive: true });

  // Initialize sql.js database (portable SQLite)
  const SQL = await initSqlJs();
  const dbPath = path.resolve(rootDir, config.dbPath || './data/vehicle_overseer.sqlite');
  let db;
  if (fs.existsSync(dbPath)) {
    db = new SQL.Database(fs.readFileSync(dbPath));
  } else {
    db = new SQL.Database();
  }
  const schemaPath = path.resolve(rootDir, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
  db.run(schemaSql);
  let dbLastMtimeMs = fs.existsSync(dbPath) ? fs.statSync(dbPath).mtimeMs : 0;

  const saveDb = () => {
    const data = db.export();
    const tmp = `${dbPath}.tmp-${process.pid}-${Date.now()}`;
    fs.writeFileSync(tmp, Buffer.from(data));
    fs.renameSync(tmp, dbPath);
    try {
      dbLastMtimeMs = fs.statSync(dbPath).mtimeMs;
    } catch {
      // ignore
    }
  };

  const maybeReloadDbFromDisk = () => {
    if (!fs.existsSync(dbPath)) return;
    const m = fs.statSync(dbPath).mtimeMs;
    if (m <= dbLastMtimeMs) return;
    const buf = fs.readFileSync(dbPath);
    try {
      db.close();
    } catch {
      // ignore
    }
    db = new SQL.Database(buf);
    db.run(schemaSql);
    dbLastMtimeMs = m;
    console.log('[db] reloaded from disk (external change detected)');
  };

  const run = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    stmt.step();
    stmt.free();
  };

  const getRow = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row;
  };

  const getArtifactById = (artifactId) => getRow(
    'SELECT id, sha256, filename, size_bytes FROM artifacts WHERE id = $id LIMIT 1',
    { $id: artifactId }
  );

  const getDeviceKeyByUid = (deviceUid) => getRow(
    'SELECT key_b64, key_id FROM device_keys WHERE device_uid = $uid LIMIT 1',
    { $uid: deviceUid }
  );

  const getRows = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  };

  const resolvePositiveNumber = (value, fallback) => {
    const num = Number(value);
    return Number.isFinite(num) && num > 0 ? num : fallback;
  };

  // In-memory live state of entries
  const entries = new Map();
  const devicePingIntervalS = resolvePositiveNumber(
    process.env.VO_DEVICE_PING_INTERVAL_S ??
      config.devicePingIntervalS ??
      config.pingIntervalS,
    10
  );
  const OFFLINE_TIMEOUT_MS = Math.round((devicePingIntervalS + 2) * 1000);
  const deviceActionPort = config.deviceActionPort;
  const deviceLogPort = config.deviceLogPort;

  const artifactsDir = path.resolve(dataDir, 'artifacts');
  fs.mkdirSync(artifactsDir, { recursive: true });

  const computeFileSha256 = (filePath) => {
    const hash = crypto.createHash('sha256');
    hash.update(fs.readFileSync(filePath));
    return hash.digest('hex');
  };

  let tarAvailable = true;
  const readVersionFromArtifact = (filePath) => {
    if (!tarAvailable) return null;
    for (const candidate of ['VERSION', './VERSION', 'version.txt', './version.txt']) {
      const proc = spawnSync('tar', ['-xOzf', filePath, candidate], { encoding: 'utf-8' });
      if (proc.error) {
        if (proc.error.code === 'ENOENT') {
          tarAvailable = false;
          console.warn('[artifacts] tar not found; cannot inspect versions');
          return null;
        }
        continue;
      }
      if (proc.status === 0) {
        const value = String(proc.stdout || '').trim();
        if (value) return value;
      }
    }
    return null;
  };

  const reconcileArtifacts = () => {
    let changed = false;
    const diskArtifacts = new Map();
    const entriesOnDisk = fs.readdirSync(artifactsDir);
    for (const name of entriesOnDisk) {
      const filePath = path.join(artifactsDir, name);
      const st = fs.statSync(filePath);
      if (!st.isFile()) continue;
      const sha = computeFileSha256(filePath);
      let finalName = name;
      let finalPath = filePath;
      if (sha !== name) {
        const targetPath = path.join(artifactsDir, sha);
        if (!fs.existsSync(targetPath)) {
          fs.renameSync(filePath, targetPath);
          finalName = sha;
          finalPath = targetPath;
        } else {
          console.warn(`[artifacts] hash mismatch for ${name}; expected ${sha} (keeping existing ${sha})`);
          continue;
        }
      }
      diskArtifacts.set(sha, { id: sha, path: finalPath, sizeBytes: st.size, filename: finalName });
    }

    const dbArtifacts = getRows('SELECT id, sha256, filename, size_bytes FROM artifacts');
    const dbArtifactsMap = new Map(dbArtifacts.map((row) => [String(row.id), row]));

    for (const row of dbArtifacts) {
      const id = String(row.id);
      if (!diskArtifacts.has(id)) {
        run('DELETE FROM versions WHERE artifact_id = $id', { $id: id });
        run('DELETE FROM artifacts WHERE id = $id', { $id: id });
        changed = true;
      }
    }

    for (const [id, info] of diskArtifacts.entries()) {
      const existing = dbArtifactsMap.get(id);
      if (!existing) {
        run(
          `INSERT INTO artifacts (id, sha256, filename, size_bytes, created_at)
           VALUES ($id, $sha, $fn, $sz, datetime('now'))`,
          {
            $id: id,
            $sha: id,
            $fn: info.filename,
            $sz: info.sizeBytes
          }
        );
        changed = true;
      } else if (Number(existing.size_bytes) !== info.sizeBytes || String(existing.sha256) !== id) {
        run(
          `UPDATE artifacts
           SET sha256 = $sha, size_bytes = $sz
           WHERE id = $id`,
          { $id: id, $sha: id, $sz: info.sizeBytes }
        );
        changed = true;
      }
    }

    const existingVersions = new Map();
    for (const row of getRows('SELECT version, artifact_id FROM versions')) {
      const version = String(row.version);
      if (version === 'latest') continue;
      existingVersions.set(version, String(row.artifact_id));
    }

    for (const [id, info] of diskArtifacts.entries()) {
      const version = readVersionFromArtifact(info.path);
      if (!version) continue;
      if (!existingVersions.has(version)) {
        run(
          `INSERT INTO versions (version, artifact_id, created_at, notes)
           VALUES ($v, $aid, datetime('now'), NULL)`,
          { $v: version, $aid: id }
        );
        existingVersions.set(version, id);
        changed = true;
      }
    }

    const newest = getRow(
      `SELECT version, artifact_id
       FROM versions
       WHERE version != 'latest'
       ORDER BY datetime(created_at) DESC, version DESC
       LIMIT 1`
    );
    if (newest?.version && newest?.artifact_id) {
      const latest = getRow('SELECT artifact_id FROM versions WHERE version = $v LIMIT 1', { $v: 'latest' });
      if (!latest || String(latest.artifact_id) !== String(newest.artifact_id)) {
        run(
          `INSERT OR REPLACE INTO versions (version, artifact_id, created_at, notes)
           VALUES ($v, $aid, datetime('now'), NULL)`,
          { $v: 'latest', $aid: newest.artifact_id }
        );
        changed = true;
      }
    }

    if (changed) {
      saveDb();
      console.log('[artifacts] reconciled artifacts and versions');
    }
  };

  reconcileArtifacts();

  const getClientConfig = () => ({
    sshUser: config.defaultSshUser ?? null,
    serviceName: config.defaultServiceName ?? null,
    mqttKey: config.defaultMqttKey ?? null,
    ipList: Array.isArray(config.ipList) ? config.ipList : [],
    deviceActionPort: deviceActionPort ?? null,
    deviceLogPort: deviceLogPort ?? null,
    devicePingIntervalS,
    offlineTimeoutMs: OFFLINE_TIMEOUT_MS
  });

  const safeName = (value, label) => {
    if (typeof value !== 'string' || !/^[A-Za-z0-9._-]+$/.test(value)) {
      throw new Error(`${label} must match /^[A-Za-z0-9._-]+$/`);
    }
    return value;
  };

  const isLoopbackPeer = (addr) => {
    if (!addr) return false;
    return (
      addr === '127.0.0.1' ||
      addr === '::1' ||
      addr === '::ffff:127.0.0.1'
    );
  };


  const createBootstrapToken = ({ kind }) => {
    const token = crypto.randomBytes(24).toString('base64url');
    run(
      `INSERT INTO bootstrap_tokens (token, kind, created_at, used_at)
       VALUES ($t, $kind, datetime('now'), NULL)`,
      { $t: token, $kind: kind }
    );
    saveDb();
    return token;
  };

  const resolveUpdateTarget = (deviceUid) => {
    const row = getRow(
      `SELECT desired_version
       FROM device_targets
       WHERE device_uid = $uid
       LIMIT 1`,
      { $uid: deviceUid }
    );
    return { desiredVersion: row?.desired_version ?? null };
  };

  const resolveArtifact = ({ desiredVersion }) => {
    let version = desiredVersion;
    if (version === 'latest') version = null;
    if (!version) {
      const latest = getRow(
        `SELECT version
         FROM versions
         WHERE version != 'latest'
         ORDER BY datetime(created_at) DESC, version DESC
         LIMIT 1`,
        {}
      );
      version = latest?.version || null;
    }
    if (!version) return null;
    return getRow(
      `SELECT
         v.version AS version,
         a.id AS artifactId,
         a.filename AS filename,
         a.sha256 AS sha256,
         a.size_bytes AS size_bytes,
         v.created_at AS created_at
       FROM versions v
       JOIN artifacts a ON a.id = v.artifact_id
       WHERE v.version = $version
       LIMIT 1`,
      { $version: version }
    );
  };

  const computeStatus = (entry) => (Date.now() - entry.lastUpdate > OFFLINE_TIMEOUT_MS ? 'offline' : 'online');

  const serializeEntry = (entry) => ({
    uid: entry.uid,
    label: entry.label || null,
    ip: entry.ip,
    selectedIp: entry.selectedIp || null,
    state: entry.state || 'not implemented',
    data: entry.data || {},
    lastUpdate: entry.lastUpdate,
    status: computeStatus(entry),
    lastError: entry.lastError || null,
    stage: entry.stage || null
  });

  // WebSocket broadcast helper
  const broadcast = (payload) => {
    if (payload && typeof payload === 'object' && payload.serverNow === undefined) {
      payload.serverNow = Date.now();
    }
    const msg = JSON.stringify(payload);
    wsServer.clients.forEach((client) => {
      if (client.readyState === 1) client.send(msg);
    });
  };

  // HTTP handlers
  async function parseJson(req) {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk.toString(); });
      req.on('end', () => {
        if (!body) return resolve({});
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  async function handleRequest(req, res) {
    const parsedUrl = new url.URL(req.url, `http://${req.headers.host}`);
    const { pathname } = parsedUrl;

    try {
      maybeReloadDbFromDisk();
    } catch (err) {
      console.warn('[db] reload failed', { err: err.message });
    }

    if (req.method !== 'OPTIONS' && pathname !== '/api/ping') {
      const start = Date.now();
      const peer = `${req.socket.remoteAddress || 'unknown'}:${req.socket.remotePort || ''}`;
      res.on('finish', () => {
        const ms = Date.now() - start;
        const qs = parsedUrl.search || '';
        console.log(`[http] ${peer} ${req.method} ${pathname}${qs} -> ${res.statusCode} (${ms}ms)`);
      });
    }

    // Simple CORS for local testing
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    if (pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    }

    if (pathname === '/api/config' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(getClientConfig()));
    }

    if (pathname === '/api/srvcsetup' && req.method === 'GET') {
      const searchParams = new url.URL(req.url, `http://${req.headers.host}`).searchParams;
      const label = searchParams.get('label');
      if (!label) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('label required\n');
      }
      let token = searchParams.get('token') || '';
      if (!token) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('token required\n');
      }
      const reportIface = searchParams.get('reportIface') || searchParams.get('report_iface') || 'tun0';
      const actionPort = Number(searchParams.get('actionPort') || searchParams.get('action_port') || 9000);
      const logPort = Number(searchParams.get('logPort') || searchParams.get('log_port') || 9100);
      const pingIntervalS = resolvePositiveNumber(
        searchParams.get('pingIntervalS') || searchParams.get('ping_interval_s'),
        devicePingIntervalS
      );

      const backendBase = `http://${req.headers.host}`;
      const installRoot = '/opt/vehicle-overseer-device';
      const envDir = '/etc/vehicle-overseer';
      const shQuote = (s) => `'${String(s).replace(/'/g, `'\"'\"'`)}'`;
      const tmplPath = path.join(rootDir, 'tools', 'srvcsetup.sh');
      const template = fs.readFileSync(tmplPath, 'utf-8');
      const script = template
        .replaceAll('__BACKEND_BASE__', shQuote(backendBase))
        .replaceAll('__LABEL__', shQuote(label))
        .replaceAll('__TOKEN__', shQuote(token))
        .replaceAll('__REPORT_IFACE__', shQuote(reportIface))
	        .replaceAll('__ACTION_PORT__', String(actionPort))
	        .replaceAll('__LOG_PORT__', String(logPort))
        .replaceAll('__PING_INTERVAL_S__', String(pingIntervalS))
	        .replaceAll('__INSTALL_ROOT__', shQuote(installRoot))
        .replaceAll('__ENV_DIR__', shQuote(envDir));

      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(script);
    }

    if (pathname === '/api/bootstrap-token' && req.method === 'POST') {
      try {
        const peer = req.socket.remoteAddress || '';
        if (!isLoopbackPeer(peer)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'forbidden' }));
        }
        const payload = await parseJson(req);
        const kind = payload.kind || 'one-time';
        if (kind !== 'one-time' && kind !== 'dev') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'kind must be one-time or dev' }));
        }
        const token = createBootstrapToken({ kind });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true, kind, token }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'token error', details: err.message }));
      }
    }

    if (pathname.startsWith('/api/srvcsetup/files/') && req.method === 'GET') {
      try {
        const name = pathname.split('/').pop();
        const allowed = new Set([
          'vehicle-overseer-device.service',
          'vo-updater.service',
          'vo-updater.timer',
          'vo_updater.py',
          'device.env',
          'updater.env'
        ]);
        if (!allowed.has(name)) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end('not found\n');
        }

        const sp = new url.URL(req.url, `http://${req.headers.host}`).searchParams;
        const backendBase = `http://${req.headers.host}`;

        if (name === 'device.env') {
          const label = sp.get('label') || '';
          const reportIface = sp.get('reportIface') || sp.get('report_iface') || 'tun0';
          const actionPort = Number(sp.get('actionPort') || sp.get('action_port') || 9000);
          const logPort = Number(sp.get('logPort') || sp.get('log_port') || 9100);
          const pingIntervalS = resolvePositiveNumber(
            sp.get('pingIntervalS') || sp.get('ping_interval_s'),
            devicePingIntervalS
          );
          const content = [
            `VO_BACKEND=${backendBase}`,
            `VO_LABEL=${label}`,
            `VO_REPORT_IFACE=${reportIface}`,
            `VO_WAIT_TIMEOUT_S=0`,
            `VO_ACTION_PORT=${actionPort}`,
            `VO_LOG_PORT=${logPort}`,
            `VO_JSONPATH=/opt/${label}/properties.json`,
            `VO_MQTT_KEY=${config.defaultMqttKey}`,
            `VO_PING_INTERVAL_S=${pingIntervalS}`,
            `VO_BIND_HOST=auto`,
            `VO_DEVICE_UID_PATH=/etc/vehicle-overseer/device.uid`,
            ``
          ].join('\n');
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end(content);
        }

	        if (name === 'updater.env') {
	          const content = [
	            `VO_INSTALL_ROOT=/opt/vehicle-overseer-device`,
	            `VO_ARTIFACT_KEY_PATH=/etc/vehicle-overseer/artifact.key`,
	            `VO_DEVICE_UID_PATH=/etc/vehicle-overseer/device.uid`,
	            ``
	          ].join('\n');
	          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
	          return res.end(content);
	        }

        const filePath = name === 'vo_updater.py'
          ? path.join(rootDir, 'tools', 'vo_updater.py')
          : path.join(rootDir, 'tools', 'systemd', name);
        const content = fs.readFileSync(filePath, 'utf-8');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(content);
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(`error: ${err.message}\n`);
      }
    }

    if (pathname === '/api/entries' && req.method === 'GET') {
      const list = Array.from(entries.values()).map(serializeEntry);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ entries: list }));
    }

    if (pathname === '/api/ping' && req.method === 'POST') {
      try {
        const payload = await parseJson(req);
        const uid = payload.uid;
        if (!uid) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'uid required' }));
        }
        const now = Date.now();
        const existing = entries.get(uid) || {};
        const entry = {
          ...existing,
          uid,
          label: payload.label || existing.label,
          ip: payload['ip-address'] || payload.ip || existing.ip,
          state: payload.state || existing.state,
          data: payload.data || existing.data,
          selectedIp: existing.selectedIp,
          // POST pings are independent of actions; do not accept action results here.
          lastError: existing.lastError,
          stage: existing.stage,
          lastUpdate: now
        };
        entries.set(uid, entry);
        broadcast({ type: 'entry', entry: serializeEntry(entry) });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid json', details: err.message }));
      }
    }

	    if (pathname === '/api/device/key' && req.method === 'GET') {
	      try {
	        const searchParams = new url.URL(req.url, `http://${req.headers.host}`).searchParams;
	        const token = searchParams.get('token') || '';
	        if (!token) {
	          res.writeHead(403, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'forbidden' }));
	        }

	        const tokenRow = getRow(
	          `SELECT token, kind, used_at
	           FROM bootstrap_tokens
	           WHERE token = $t
	           LIMIT 1`,
	          { $t: token }
	        );
	        if (!tokenRow) {
	          res.writeHead(403, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'forbidden' }));
	        }
	        const kind = String(tokenRow.kind || 'one-time');
	        const isDev = kind === 'dev';
	        if (!isDev && tokenRow.used_at) {
	          res.writeHead(403, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'forbidden' }));
	        }

	        const deviceUid = crypto.randomBytes(16).toString('hex');
	        const keyB64 = crypto.randomBytes(32).toString('base64');
	        const keyId = crypto.randomBytes(8).toString('hex');
	        run(
	          `INSERT INTO device_keys (device_uid, key_id, key_b64, created_at, updated_at)
	           VALUES ($uid, $key_id, $key_b64, datetime('now'), datetime('now'))`,
	          { $uid: deviceUid, $key_id: keyId, $key_b64: keyB64 }
	        );

	        if (!isDev) {
	          run(
	            `UPDATE bootstrap_tokens
	             SET used_at = datetime('now')
	             WHERE token = $t AND used_at IS NULL`,
	            { $t: token }
	          );
	        }
	        saveDb();

        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(`${deviceUid}\n${keyB64}\n`);
	      } catch (err) {
	        res.writeHead(500, { 'Content-Type': 'application/json' });
	        return res.end(JSON.stringify({ error: 'key error', details: err.message }));
	      }
	    }

	    if (pathname === '/api/device/manifest' && req.method === 'GET') {
	      try {
	        const searchParams = new url.URL(req.url, `http://${req.headers.host}`).searchParams;
	        const deviceUid = searchParams.get('uid');
	        if (!deviceUid) {
	          res.writeHead(400, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'uid required' }));
	        }

	        const { desiredVersion } = resolveUpdateTarget(deviceUid);
	        const artifact = resolveArtifact({ desiredVersion });
	        if (!artifact) {
	          res.writeHead(404, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({
	            error: 'no artifact available',
	            hint: 'Import a version into the backend DB and store the package bytes at backend/data/artifacts/<sha256>.'
	          }));
	        }

          const artifactPath = `/api/device/artifacts/${encodeURIComponent(artifact.artifactId)}`;
	        const manifest = {
	          uid: deviceUid,
	          version: artifact.version,
	          artifact: {
	            id: artifact.artifactId,
	            url: artifactPath,
	            sha256: artifact.sha256,
	            filename: artifact.filename,
	            sizeBytes: artifact.size_bytes
	          },
	          issuedAt: new Date().toISOString()
	        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(manifest));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'manifest error', details: err.message }));
      }
    }

	    if (pathname.startsWith('/api/device/artifacts/') && req.method === 'GET') {
	      try {
	        const parts = pathname.split('/').filter(Boolean);
	        if (parts.length !== 4) {
	          res.writeHead(400, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'invalid artifact path' }));
	        }
	        const artifactId = safeName(decodeURIComponent(parts[3]), 'artifactId');
	        const artifact = getArtifactById(artifactId);
	        if (!artifact) {
	          res.writeHead(404, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'artifact not found' }));
	        }

	        const filePath = path.resolve(artifactsDir, artifactId);
	        if (!filePath.startsWith(path.resolve(artifactsDir) + path.sep) || !fs.existsSync(filePath)) {
	          res.writeHead(404, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'artifact file missing on server' }));
	        }

	        const searchParams = new url.URL(req.url, `http://${req.headers.host}`).searchParams;
	        const deviceUid = searchParams.get('uid');
	        if (!deviceUid) {
	          res.writeHead(403, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'uid required' }));
	        }
	        const keyRow = getDeviceKeyByUid(deviceUid);
	        if (!keyRow?.key_b64) {
	          res.writeHead(403, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'key not found' }));
	        }
	        const maybeKey = Buffer.from(String(keyRow.key_b64), 'base64');
	        if (maybeKey.length !== 32) {
	          res.writeHead(500, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'invalid key length' }));
	        }
	        const ivHex = crypto.randomBytes(16).toString('hex');

	        res.writeHead(200, {
	          'Content-Type': 'application/octet-stream',
	          'Content-Length': artifact.size_bytes,
	          'X-Artifact-Sha256': artifact.sha256,
	          'X-VO-Enc': 'aes-256-ctr',
	          'X-VO-Iv': ivHex,
	          ...(keyRow?.key_id ? { 'X-VO-KeyId': String(keyRow.key_id) } : {})
	        });

	        const stream = fs.createReadStream(filePath);
	        const iv = Buffer.from(ivHex, 'hex');
	        const cipher = crypto.createCipheriv('aes-256-ctr', maybeKey, iv);
	        stream.pipe(cipher).pipe(res);
	        return;
	      } catch (err) {
	        res.writeHead(500, { 'Content-Type': 'application/json' });
	        return res.end(JSON.stringify({ error: 'artifact error', details: err.message }));
	      }
	    }

    if (pathname === '/api/action/select' && req.method === 'POST') {
      try {
        const payload = await parseJson(req);
        const uid = payload.uid;
        const ip = payload.ip;
        if (!uid || !ip) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'uid and ip required' }));
        }
        const entry = entries.get(uid);
	        if (!entry) {
	          res.writeHead(404, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ error: 'entry not found' }));
	        }
	        entry.selectedIp = ip;
	        entries.set(uid, entry);

        const deviceHost = entry.ip;
        const resolvedActionPort = (
          entry?.data?.actionPort ??
          entry?.data?.action_port ??
          deviceActionPort
        );

	        if (!deviceHost || !resolvedActionPort) {
	          entry.lastError = 'No device action endpoint configured (missing ip or deviceActionPort)';
	          entry.stage = null;
	          broadcast({ type: 'entry', entry: serializeEntry(entry) });
	          res.writeHead(200, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ ok: false, error: entry.lastError }));
	        }

        const setStage = (stage) => {
          entry.stage = stage;
          entries.set(uid, entry);
          broadcast({ type: 'entry', entry: serializeEntry(entry) });
        };

        const clearStageSoon = () => {
          setTimeout(() => {
            entry.stage = null;
            entries.set(uid, entry);
            broadcast({ type: 'entry', entry: serializeEntry(entry) });
          }, 1500);
        };

        setStage('connecting');
        const result = await new Promise((resolve) => {
          const socket = net.createConnection({ host: deviceHost, port: Number(resolvedActionPort) }, () => {
            setStage('applying');
            socket.write(`${JSON.stringify({ uid, ip })}\n`);
          });

          socket.setTimeout(8000, () => {
            socket.destroy(new Error('timeout'));
          });

          let buf = '';
          socket.on('data', (chunk) => { buf += chunk.toString('utf-8'); });
          socket.on('error', (err) => resolve({ ok: false, error: err.message || 'connect failed' }));
          socket.on('close', () => {
            const line = buf.split('\n').find((l) => l.trim().length > 0);
            if (!line) return resolve({ ok: false, error: 'empty response from device' });
            try {
              resolve(JSON.parse(line));
            } catch {
              resolve({ ok: false, error: line.trim() });
            }
          });
        });

	        if (result.ok) {
	          entry.lastError = null;
	          setStage('success');
	          clearStageSoon();
	          res.writeHead(200, { 'Content-Type': 'application/json' });
	          return res.end(JSON.stringify({ ok: true }));
	        }

	        entry.lastError = result.error || 'device error';
	        entry.stage = null;
	        entries.set(uid, entry);
	        broadcast({ type: 'entry', entry: serializeEntry(entry) });
	        res.writeHead(200, { 'Content-Type': 'application/json' });
	        return res.end(JSON.stringify({ ok: false, error: entry.lastError }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid json', details: err.message }));
      }
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  }

  // HTTP + WS servers
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      console.error('Request error', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'server error' }));
    });
  });

  const wsServer = new WebSocketServer({ noServer: true });
const logServer = new WebSocketServer({ noServer: true });

  wsServer.on('connection', (socket) => {
    const snapshot = Array.from(entries.values()).map(serializeEntry);
    socket.send(JSON.stringify({
      type: 'init',
      entries: snapshot,
      config: getClientConfig(),
      serverNow: Date.now()
    }));
  });

  logServer.on('connection', (socket, request) => {
    const { searchParams, pathname } = new url.URL(request.url, `http://${request.headers.host}`);
    let uid = searchParams.get('uid');
    if (!uid && pathname.startsWith('/logs/')) {
      uid = pathname.split('/').pop();
    }
    const entry = uid ? entries.get(uid) : null;
    if (!uid || !entry) {
      socket.send(JSON.stringify({ error: 'uid not found' }));
      return socket.close();
    }

    const logHost = entry.ip;
    const resolvedLogPort = (
      entry?.data?.logPort ??
      entry?.data?.log_port ??
      deviceLogPort
    );

    if (!logHost || !resolvedLogPort) {
      socket.send(`[backend] no log endpoint configured for ${uid}`);
      return socket.close();
    }

    const upstream = net.createConnection({ host: logHost, port: Number(resolvedLogPort) });

    let buf = '';
    const flushLines = () => {
      const parts = buf.split('\n');
      buf = parts.pop() || '';
      for (const line of parts) {
        const trimmed = line.replace(/\r$/, '');
        if (trimmed.length) socket.send(trimmed);
      }
    };

    upstream.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      flushLines();
    });
    upstream.on('error', (err) => {
      socket.send(`[backend] log upstream error: ${err.message || 'error'}`);
      socket.close();
    });
    upstream.on('close', () => socket.close());

    socket.on('close', () => upstream.destroy());
  });

  server.on('upgrade', (req, socket, head) => {
    const { pathname } = new url.URL(req.url, `http://${req.headers.host}`);
    console.log(`[ws] ${req.socket.remoteAddress || 'unknown'} upgrade ${pathname}`);
    if (pathname === '/ws') {
      wsServer.handleUpgrade(req, socket, head, (ws) => wsServer.emit('connection', ws, req));
    } else if (pathname.startsWith('/logs')) {
      logServer.handleUpgrade(req, socket, head, (ws) => logServer.emit('connection', ws, req));
    } else {
      socket.destroy();
    }
  });

  // Offline monitor
  setInterval(() => {
    entries.forEach((entry) => {
      const status = computeStatus(entry);
      if (entry._lastBroadcastStatus !== status) {
        entry._lastBroadcastStatus = status;
        broadcast({ type: 'entry', entry: serializeEntry(entry) });
      }
    });
  }, 1000);

  const host = process.env.VO_HTTP_HOST || config.httpHost || '127.0.0.1';
  const port = Number(process.env.VO_HTTP_PORT || config.httpPort || 8080);
  server.listen(port, host, () => {
    console.log(`Backend listening on ${host}:${port}`);
    console.log('HTTP endpoints: GET /api/config, GET /api/entries, POST /api/ping, POST /api/action/select, GET /api/device/manifest, GET /api/device/artifacts/<id>, GET /api/device/key, POST /api/bootstrap-token');
    console.log('WebSockets: ws://host:port/ws (updates), ws://host:port/logs?uid=UID (per-device logs)');
  });
}

main().catch((err) => {
  console.error('Fatal startup error', err);
  process.exit(1);
});
