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
  artifacts import <file> [--force]   import artifact and sync to database (force overwrites version mapping)
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

function readFileDateFromTarGzBytes(bytes, candidates) {
  const proc = spawnSync('tar', ['--full-time', '-tzvf', '-'], {
    encoding: 'utf-8',
    input: bytes,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  let date = null;
  if (proc.status === 0 && proc.stdout) {
    const lines = String(proc.stdout || '').split('\n');
    for (const candidate of candidates) {
      for (const line of lines) {
        if (line.includes(candidate)) {
          const match = line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
          if (match) {
            const parsed = new Date(match[1]);
            if (!Number.isNaN(parsed.getTime())) date = parsed.toISOString();
          }
          break;
        }
      }
    }
  }
  return date;
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

function readVersionAndDateFromArtifact(filePath) {
  // Read VERSION content and its timestamp from inner tar.gz; no filesystem fallback
  const dat = readFileFromTar(filePath, './data', { encoding: 'buffer' });
  return dat ? {
    version: readFileFromTarGzBytes(dat, ['./VERSION']),
    date: readFileDateFromTarGzBytes(dat, ['./VERSION'])
  } : { version: null, date: null };
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

function upsertArtifact(run, { id, filename, sizeBytes, createdAt, mode }) {
  if (!createdAt) throw new Error('createdAt required for artifact');

  if (mode === 'refresh') {
    run(
      `INSERT OR IGNORE INTO artifacts (id, filename, size_bytes, created_at, inserted_at)
       VALUES ($id, $fn, $sz, $ca, datetime('now'))`,
      { $id: id, $fn: filename, $sz: sizeBytes, $ca: createdAt }
    );
    return;
  }

  // import: replace artifact metadata with provided created_at
  run(
    `INSERT OR REPLACE INTO artifacts (id, filename, size_bytes, created_at, inserted_at)
     VALUES ($id, $fn, $sz, $ca, datetime('now'))`,
    { $id: id, $fn: filename, $sz: sizeBytes, $ca: createdAt }
  );
}

function upsertArtifactAndVersion(run, mode, id, version, filename, sizeBytes, createdAt, options = {}) {
  if (!version) return { versionInserted: false, conflictInfo: null };

  const { getRow = null, force = false } = options;
  let conflictInfo = null;

  if (mode === 'import' && typeof getRow === 'function') {
    const existingVersion = getRow('SELECT artifact_id FROM versions WHERE version = $v LIMIT 1', { $v: version });
    if (existingVersion && String(existingVersion.artifact_id) !== String(id)) {
      const existingArtifact = getRow('SELECT id, size_bytes, created_at FROM artifacts WHERE id = $id LIMIT 1', {
        $id: existingVersion.artifact_id
      });
      conflictInfo = existingArtifact
        ? {
            existingId: String(existingArtifact.id),
            existingSize: Number(existingArtifact.size_bytes),
            existingCreatedAt: String(existingArtifact.created_at)
          }
        : { existingId: String(existingVersion.artifact_id), existingSize: null, existingCreatedAt: null };
      if (!force) {
        throw new Error(
          `version ${version} already mapped to artifact ${conflictInfo.existingId}; use --force to overwrite`
        );
      }
    }
  }

  if (mode === 'refresh') {
    upsertArtifact(run, { id, filename, sizeBytes, createdAt, mode });
    run(
      `INSERT INTO versions (version, artifact_id, notes)
       VALUES ($v, $id, NULL)`,
      { $v: version, $id: id }
    );
    return { versionInserted: true, conflictInfo };
  }

  // import: upsert artifact + version
  upsertArtifact(run, { id, filename, sizeBytes, createdAt, mode: 'import' });
  run(
    `INSERT OR REPLACE INTO versions (version, artifact_id, notes)
     VALUES ($v, $id, NULL)`,
    { $v: version, $id: id }
  );
  return { versionInserted: true, conflictInfo };
}

function updateLatest(db) {
  // Maintain synthetic 'latest' using artifact created_at, falling back to version desc.
  const newestStmt = db.prepare(
    `SELECT v.version AS version, v.artifact_id AS artifact_id
     FROM versions v
     JOIN artifacts a ON a.id = v.artifact_id
     WHERE v.version != 'latest'
     ORDER BY datetime(a.created_at) DESC, v.version DESC
     LIMIT 1`
  );
  const hasNewest = newestStmt.step();
  const newest = hasNewest ? newestStmt.getAsObject() : null;
  newestStmt.free();
  if (!newest?.version || !newest?.artifact_id) return;

  const upsert = db.prepare(
    `INSERT OR REPLACE INTO versions (version, artifact_id, notes)
     VALUES ('latest', $id, NULL)`
  );
  upsert.bind({ $id: newest.artifact_id });
  upsert.step();
  upsert.free();
}

async function cmdImport({ rootDir, config, filePath, force }) {
  const resolvedFile = path.resolve(filePath);
  if (!fs.existsSync(resolvedFile) || !fs.statSync(resolvedFile).isFile()) {
    throw new Error(`file not found: ${resolvedFile}`);
  }

  // Read id from hash file inside tarball
  const id = readIdFromArtifact(resolvedFile);
  if (!id) {
    throw new Error('hash file not found in artifact');
  }

  // Read version + date from tarball
  const { version, date } = readVersionAndDateFromArtifact(resolvedFile);
  if (!version || !date) {
    throw new Error('data or VERSION file not found in artifact or missing timestamp');
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

  const getRow = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const has = stmt.step();
    const row = has ? stmt.getAsObject() : null;
    stmt.free();
    return row;
  };

  const run = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    stmt.step();
    stmt.free();
  };

  run('BEGIN');
  let conflictInfo = null;
  try {
    const result = upsertArtifactAndVersion(run, 'import', id, version, filename, sizeBytes, date, { getRow, force });
    conflictInfo = result?.conflictInfo ?? null;
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

  if (conflictInfo) {
    process.stderr.write(
      `[import] version ${version} overwrite - disk: ${id} (size ${sizeBytes} bytes, date ${date}), db: ${conflictInfo.existingId} (size ${conflictInfo.existingSize ?? 'unknown'} bytes, date ${conflictInfo.existingCreatedAt ?? 'unknown'})\n`
    );
  }

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
    const { version, date } = readVersionAndDateFromArtifact(filePath);
    diskArtifacts.set(id, { path: filePath, filename, sizeBytes: st.size, version, createdAt: date, status: 'new' });
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
      upsertArtifact(run, { id, filename: info.filename, sizeBytes: info.sizeBytes, createdAt: info.createdAt, mode: 'refresh' });
      if (isNew) {
        process.stderr.write(`[refresh] added artifact: ${id}\n`);
        info.status = 'inserted';
        added++;
      } else {
        info.status = 'present';
      }
    }

    // Populate versions from VERSION files
    const existingVersions = new Map();
    const versionRows = getRows(
      `SELECT v.version AS version, v.artifact_id AS artifact_id, a.size_bytes AS size_bytes, a.created_at AS created_at
       FROM versions v
       LEFT JOIN artifacts a ON a.id = v.artifact_id`
    );
    for (const row of versionRows) {
      const version = String(row.version);
      if (version === 'latest') continue;
      existingVersions.set(version, {
        artifactId: String(row.artifact_id),
        sizeBytes: Number(row.size_bytes),
        createdAt: String(row.created_at)
      });
    }

    for (const [id, info] of diskArtifacts.entries()) {
      if (!info.version || !info.createdAt) {
        process.stderr.write(`[refresh] warn: no VERSION found in ${id}\n`);
        info.status = 'no_version';
        continue;
      }

      const existingEntry = existingVersions.get(info.version);
      if (existingEntry) {
        if (String(existingEntry.artifactId) === String(id)) {
          continue;
        }
        const diskDateStr = info.createdAt || 'unknown';
        process.stderr.write(
          `[refresh] version ${info.version} conflict - disk: ${id} (size ${info.sizeBytes} bytes, date ${diskDateStr}), db: ${existingEntry.artifactId} (size ${existingEntry.sizeBytes} bytes, date ${existingEntry.createdAt})\n`
        );
        info.status = 'version_conflict';
        continue;
      }

      const { versionInserted } = upsertArtifactAndVersion(
        run, 'refresh', id, info.version, info.filename, info.sizeBytes, info.createdAt
      );
      if (versionInserted) {
        existingVersions?.set(info.version, {
          artifactId: String(id), sizeBytes: Number(info.sizeBytes), createdAt: info.createdAt,
        });
        process.stderr.write(`[refresh] added version: ${info.version} -> ${id}\n`);
      }
    }

    updateLatest(db);

    run('COMMIT');
  } catch (err) {
    try { run('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  }

  saveDbAtomic(db, dbPath);

  // Build artifacts output with status from diskArtifacts + skipped items
  const artifacts = [];

  // Add all processed artifacts from diskArtifacts
  for (const [id, info] of diskArtifacts.entries()) {
    const result = {
      id,
      filename: info.filename,
      status: info.status,
      version: info.version,
      sizeBytes: info.sizeBytes
    };
    artifacts.push(result);
  }

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
    const force = argv.includes('--force') || argv.includes('-f');
    if (!filePath) {
      process.stderr.write('error: import requires a file path\n\n');
      usage(2);
    }
    return cmdImport({ rootDir, config, filePath, force });
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

