// Backend-side artifact CLI.

import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import initSqlJs from 'sql.js';

const ARTIFACTS_DIR = 'data/artifacts';

// Usage:
//   node backend/src/index.js artifacts import /path/to/artifact-file
//   node backend/src/index.js artifacts refresh
//   ./vehicle-overseer-backend artifacts import /path/to/artifact-file
//   ./vehicle-overseer-backend artifacts refresh

function usage(exitCode = 0) {
  const msg = `Usage:
  artifacts import <file>   import artifact and sync to database
  artifacts refresh         scan ${ARTIFACTS_DIR}/ and sync to database

ID is read from hash file inside the tarball.
Version is read from VERSION file inside the tarball.
Missing artifacts are removed from SQLite on refresh.
`;
  process.stderr.write(msg);
  process.exit(exitCode);
}

function readFileFromTar(filePath, member, { encoding = 'utf-8' } = {}) {
  const proc = spawnSync('tar', ['-xOf', filePath, member], { encoding, stdio: ['pipe', 'pipe', 'pipe'] });
  if (proc.error || proc.status !== 0) return null;
  return proc.stdout;
}

function readFileFromTarGzBytes(bytes, candidates) {
  for (const candidate of candidates) {
    const proc = spawnSync('tar', ['-xOzf', '-', candidate], {
      encoding: 'utf-8',
      input: bytes,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    if (proc.error) continue;
    if (proc.status === 0) {
      const value = String(proc.stdout || '').trim();
      if (value) return value;
    }
  }
  return null;
}

function readFileFromTarGz(filePath, candidates) {
  for (const candidate of candidates) {
    const proc = spawnSync('tar', ['-xOzf', filePath, candidate], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    if (proc.error) continue;
    if (proc.status === 0) {
      const value = String(proc.stdout || '').trim();
      if (value) return value;
    }
  }
  return null;
}

function readIdFromArtifact(filePath) {
  // Outer tar must hold hash + data (inner tar.gz)
  const hashvalue = readFileFromTar(filePath, './hash');
  return hashvalue ? String(hashvalue).trim() : null;
}

function readVersionFromArtifact(filePath) {
  // VERSION lives inside inner data (tar.gz) within outer tar
  const dat = readFileFromTar(filePath, './data', { encoding: 'buffer' });
  return dat ? readFileFromTarGzBytes(dat, ['VERSION', './VERSION']) : null;
}

function openDb({ SQL, dbPath, schemaSql }) {
  let db;
  if (fs.existsSync(dbPath)) db = new SQL.Database(fs.readFileSync(dbPath));
  else db = new SQL.Database();
  db.run(schemaSql);
  return db;
}

function saveDbAtomic(db, dbPath) {
  const data = db.export();
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const tmp = `${dbPath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, Buffer.from(data));
  fs.renameSync(tmp, dbPath);
}

function upsertArtifact(run, { id, filename, sizeBytes }) {
  run(
    `INSERT OR IGNORE INTO artifacts (id, filename, size_bytes, created_at)
     VALUES ($id, $fn, $sz, datetime('now'))`,
    { $id: id, $fn: filename, $sz: sizeBytes }
  );

  run(
    `UPDATE artifacts
     SET filename = $fn, size_bytes = $sz
     WHERE id = $id`,
    { $id: id, $fn: filename, $sz: sizeBytes }
  );
}

function upsertArtifactAndVersion(run, { id, filename, sizeBytes, version, mode, existingVersions }) {
  upsertArtifact(run, { id, filename, sizeBytes });

  if (!version) return { versionInserted: false };

  if (mode === 'refresh') {
    const already = existingVersions?.has(version);
    if (already) return { versionInserted: false };
    run(
      `INSERT INTO versions (version, artifact_id, created_at, notes)
       VALUES ($v, $id, datetime('now'), NULL)`,
      { $v: version, $id: id }
    );
    existingVersions?.set(version, id);
    return { versionInserted: true };
  }

  // import: upsert version
  run(
    `INSERT OR REPLACE INTO versions (version, artifact_id, created_at, notes)
     VALUES ($v, $id, datetime('now'), NULL)`,
    { $v: version, $id: id }
  );
  return { versionInserted: true };
}

function updateLatest(db) {
  const newestStmt = db.prepare(
    `SELECT version, artifact_id
     FROM versions
     WHERE version != 'latest'
     ORDER BY datetime(created_at) DESC, version DESC
     LIMIT 1`
  );
  const hasNewest = newestStmt.step();
  const newest = hasNewest ? newestStmt.getAsObject() : null;
  newestStmt.free();
  if (!newest?.version || !newest?.artifact_id) return;

  const latestStmt = db.prepare('SELECT artifact_id FROM versions WHERE version = $v LIMIT 1');
  latestStmt.bind({ $v: 'latest' });
  const hasLatest = latestStmt.step();
  const latest = hasLatest ? latestStmt.getAsObject() : null;
  latestStmt.free();

  if (!latest || String(latest.artifact_id) !== String(newest.artifact_id)) {
    const upsert = db.prepare(
      `INSERT OR REPLACE INTO versions (version, artifact_id, created_at, notes)
       VALUES ($v, $id, datetime('now'), NULL)`
    );
    upsert.bind({ $v: 'latest', $id: newest.artifact_id });
    upsert.step();
    upsert.free();
  }
}

async function cmdImport({ rootDir, config, filePath }) {
  const resolvedFile = path.resolve(filePath);
  if (!fs.existsSync(resolvedFile) || !fs.statSync(resolvedFile).isFile()) {
    throw new Error(`file not found: ${resolvedFile}`);
  }

  // Read id from hash file inside tarball
  const id = readIdFromArtifact(resolvedFile);
  if (!id) {
    throw new Error('hash file not found in artifact');
  }

  // Read version from tarball
  const version = readVersionFromArtifact(resolvedFile);
  if (!version) {
    throw new Error('data or VERSION file not found in artifact');
  }

  const artifactsDir = path.resolve(rootDir, ARTIFACTS_DIR);
  fs.mkdirSync(artifactsDir, { recursive: true });

  const filename = path.basename(resolvedFile);
  const destPath = path.join(artifactsDir, filename);
 
  if (fs.existsSync(destPath)) {
    process.stderr.write(`[import] artifact already exists: ${id}\n`);
  } else {
    fs.copyFileSync(resolvedFile, destPath);
    process.stderr.write(`[import] copied to ${ARTIFACTS_DIR}/${filename}\n`);
  }

  const sizeBytes = fs.statSync(destPath).size;

  // Update SQLite
  const dbPath = path.resolve(rootDir, config.dbPath);
  const schemaPath = path.resolve(rootDir, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf-8');

  const SQL = await initSqlJs({
    locateFile: (file) => {
      const packaged = fs.existsSync(path.join(rootDir, file));
      if (packaged) return path.join(rootDir, file);
      return path.join(rootDir, 'node_modules', 'sql.js', 'dist', file);
    }
  });

  const db = openDb({ SQL, dbPath, schemaSql });

  const run = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    stmt.step();
    stmt.free();
  };

  run('BEGIN');
  try {
    upsertArtifactAndVersion(run, { id, filename, sizeBytes, version, mode: 'import' });
    updateLatest(db);

    run('COMMIT');
  } catch (err) {
    try { run('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  }

  saveDbAtomic(db, dbPath);

  process.stdout.write(
    JSON.stringify({ ok: true, mode: 'import', id, filename, version, sizeBytes }, null, 2) + '\n'
  );

  return 0;
}

async function cmdRefresh({ rootDir, config }) {
  const dbPath = path.resolve(rootDir, config.dbPath);
  const artifactsDir = path.resolve(rootDir, ARTIFACTS_DIR);

  const schemaPath = path.resolve(rootDir, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf-8');

  const SQL = await initSqlJs({
    locateFile: (file) => {
      const packaged = fs.existsSync(path.join(rootDir, file));
      if (packaged) return path.join(rootDir, file);
      return path.join(rootDir, 'node_modules', 'sql.js', 'dist', file);
    }
  });

  const db = openDb({ SQL, dbPath, schemaSql });

  const run = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    stmt.step();
    stmt.free();
  };

  const getRows = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  };

  const getRow = (sql, params = {}) => {
    const rows = getRows(sql, params);
    return rows.length > 0 ? rows[0] : null;
  };

  // Scan disk - read id from hash file inside each artifact
  const diskArtifacts = new Map();
  if (!fs.existsSync(artifactsDir)) {
    process.stderr.write(`[refresh] artifacts dir missing; treating as empty: ${artifactsDir}\n`);
  }

  const entriesOnDisk = fs.existsSync(artifactsDir) ? fs.readdirSync(artifactsDir) : [];
  for (const filename of entriesOnDisk) {
    const filePath = path.join(artifactsDir, filename);
    const st = fs.statSync(filePath);
    if (!st.isFile()) continue;
    const id = readIdFromArtifact(filePath);
    if (!id) {
      process.stderr.write(`[refresh] warn: no hash file in ${filename}?!, skipping\n`);
      continue;
    }
    if (diskArtifacts.has(id)) {
      process.stderr.write(`[refresh] warn: duplicate artifact ID ${id}; skipping ${filename}\n`);
      continue;
    }
    diskArtifacts.set(id, { path: filePath, filename, sizeBytes: st.size });
  }

  const dbArtifacts = getRows('SELECT id, filename FROM artifacts');
  const dbIds = new Set(dbArtifacts.map((row) => String(row.id)));

  let added = 0;
  let removed = 0;

  run('BEGIN');
  try {
    // Remove DB entries for missing artifacts (by id)
    for (const row of dbArtifacts) {
      const id = String(row.id);
      if (!diskArtifacts.has(id)) {
        run('DELETE FROM versions WHERE artifact_id = $id', { $id: id });
        run('DELETE FROM artifacts WHERE id = $id', { $id: id });
        process.stderr.write(`[refresh] removed missing artifact from DB: ${id}\n`);
        removed++;
      }
    }

    // Add/update DB entries for disk files
    for (const [id, info] of diskArtifacts.entries()) {
      const isNew = !dbIds.has(id);
      upsertArtifact(run, { id, filename: info.filename, sizeBytes: info.sizeBytes });
      if (isNew) {
        process.stderr.write(`[refresh] added artifact: ${id}\n`);
        added++;
      }
    }

    // Populate versions from VERSION files
    const existingVersions = new Map();
    for (const row of getRows('SELECT version, artifact_id FROM versions')) {
      const version = String(row.version);
      if (version === 'latest') continue;
      existingVersions.set(version, String(row.artifact_id));
    }

    for (const [id, info] of diskArtifacts.entries()) {
      let version = readVersionFromArtifact(info.path);
      if (!version) {
        process.stderr.write(`[refresh] warn: no VERSION found in ${id}\n`);
        continue;
      }
      info.version = version;
      const { versionInserted } = upsertArtifactAndVersion(run, {
        id,
        filename: info.filename,
        sizeBytes: info.sizeBytes,
        version,
        mode: 'refresh',
        existingVersions
      });
      if (versionInserted) {
        process.stderr.write(`[refresh] added version: ${version} -> ${id}\n`);
      }
    }

    // Update 'latest' pointer
    updateLatest(db);

    run('COMMIT');
  } catch (err) {
    try { run('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  }

  saveDbAtomic(db, dbPath);

  const artifacts = Array.from(diskArtifacts.entries())
    .filter(([id, info]) => info.version)
    .map(([id, info]) => ({
      id,
      filename: info.filename,
      version: info.version,
      sizeBytes: info.sizeBytes
    }));

  process.stdout.write(
    JSON.stringify({ ok: true, mode: 'refresh', added, removed, artifacts }, null, 2) + '\n'
  );

  return 0;
}

export async function runArtifactsCli({ argv, rootDir, config }) {
  const cmd = argv[0];

  if (cmd === '--help' || cmd === '-h' || !cmd) {
    usage(0);
  }

  if (cmd === 'import') {
    const filePath = argv[1];
    if (!filePath) {
      process.stderr.write('error: import requires a file path\n\n');
      usage(2);
    }
    return cmdImport({ rootDir, config, filePath });
  }

  if (cmd === 'refresh') {
    return cmdRefresh({ rootDir, config });
  }

  process.stderr.write(`error: unknown command '${cmd}'\n\n`);
  usage(2);
}

// Shared programmatic refresh (disk -> SQLite) for reuse in index.js
export async function refreshArtifacts({ rootDir, config }) {
  return cmdRefresh({ rootDir, config });
}

