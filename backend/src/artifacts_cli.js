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

function updateArtifact(run, { id, filename, sizeBytes, createdAt, version }) {
  run(
    `INSERT OR IGNORE INTO artifacts (id, filename, size_bytes, created_at, inserted_at)
     VALUES ($id, $fn, $sz, $ca, datetime('now'))`,
    { $id: id, $fn: filename, $sz: sizeBytes, $ca: createdAt }
  );
  run(
    `INSERT OR IGNORE INTO versions (version, artifact_id, notes)
     VALUES ($v, $id, NULL)`,
    { $v: version, $id: id }
  );
}

function upsertArtifact(run, { id, filename, sizeBytes, createdAt, version }) {
  run(
    `INSERT OR REPLACE INTO artifacts (id, filename, size_bytes, created_at, inserted_at)
     VALUES ($id, $fn, $sz, $ca, datetime('now'))`,
    { $id: id, $fn: filename, $sz: sizeBytes, $ca: createdAt }
  );
  run(
    `INSERT OR REPLACE INTO versions (version, artifact_id, notes)
      VALUES ($v, $id, NULL)`,
    { $v: version, $id: id }
  );
}

function upsertArtifactAndVersion(run, mode, id, version, filename, sizeBytes, createdAt, options = {}) {
  const { force = false } = options;
  let conflictInfo = null;
  let versionInserted = false;

  switch (mode) {
    case 'refresh':
      updateArtifact(run, { id, filename, sizeBytes, createdAt, version });
      versionInserted = true;
      break;

    case 'import':
      const existingVersionRows = run('SELECT artifact_id FROM versions WHERE version = $v LIMIT 1', { $v: version });
      const existingVersion = existingVersionRows?.[0];
      if (existingVersion && String(existingVersion.artifact_id) !== String(id)) {
        const existingArtifactRows = run('SELECT id, size_bytes, created_at FROM artifacts WHERE id = $id LIMIT 1', {
          $id: existingVersion.artifact_id
        });
        const existingArtifact = existingArtifactRows?.[0];
        conflictInfo = existingArtifact
          ? {
              existingId: String(existingArtifact.id),
              existingSize: Number(existingArtifact.size_bytes),
              existingCreatedAt: String(existingArtifact.created_at)
            }
          : { existingId: String(existingVersion.artifact_id), existingSize: null, existingCreatedAt: null };
        if (!force) {
          return null;
        }
      }

      upsertArtifact(run, { id, filename, sizeBytes, createdAt, version });

      versionInserted = true;
      break;

    default:
      throw new Error(`unknown mode for upsertArtifactAndVersion: ${mode}`);
  }

  return { versionInserted, conflictInfo };
}

function updateLatest(run) {
  // Maintain synthetic 'latest' using artifact created_at, falling back to version desc.
  const rows = run(
    `SELECT v.version AS version, v.artifact_id AS artifact_id
     FROM versions v JOIN artifacts a ON a.id = v.artifact_id
     WHERE v.version != 'latest'
     ORDER BY datetime(a.created_at) DESC, v.version DESC
     LIMIT 1`
  );
  process.stdout.write('rows -> ' + JSON.stringify(rows) + '\n');
  const newest = rows?.length ? rows[0] : {};
  if (!newest?.version || !newest?.artifact_id) return;
  run(
    `INSERT OR REPLACE INTO versions (version, artifact_id, notes)
     VALUES ('latest', $id, NULL)`,
    { $id: newest.artifact_id }
  );
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

  const run = (sqlquery, params = {}) => {
    // process.stdout.write('run('+sqlquery+') -> ' + JSON.stringify(params) + '\n');
    const stmt = db.prepare(sqlquery);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows.length ? rows : undefined;
  };

  run('BEGIN');
  let conflictInfo = null;
  let versionInserted = false;
  let upsertResult = upsertArtifactAndVersion(run, 'import', id, version, filename, sizeBytes, date, { force });
  if (upsertResult === null) {
    // Conflict, not forced
    try { run('ROLLBACK'); } catch { /* ignore */ }
    const msg = `version ${version} already mapped to artifact (use --force to overwrite)`;
    process.stderr.write(msg + '\n');
    process.stdout.write(
      JSON.stringify({ ok: false, mode: 'import', id, filename, version, sizeBytes, conflict: true, message: msg }, null, 2) + '\n'
    );
    return 0;
  } else {
    versionInserted = upsertResult.versionInserted;
    conflictInfo = upsertResult.conflictInfo;
  }

  updateLatest(run);
  run('COMMIT');

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

  const run = (sqlquery, params = {}) => {
    // process.stdout.write('run('+sqlquery+') -> ' + JSON.stringify(params) + '\n');
    const stmt = db.prepare(sqlquery);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows.length ? rows : undefined;
  };

  // Scan disk - read id from hash file inside each artifact
  const artifactsDir = path.resolve(rootDir, ARTIFACTS_DIR);
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
    // process.stderr.write(`${id} -> ${version} ${date}\n`);

    if (!version || !date) {
      process.stderr.write(`[refresh] warn: no VERSION found in ${id}\n`);
    }
    diskArtifacts.set(id, { path: filePath, filename, sizeBytes: st.size, version, createdAt: date, status: 'new' });
  }

  // get list of artifacts from DB
  const dbArtifacts = run('SELECT id FROM artifacts') || [];
  const dbIds = new Set(dbArtifacts.map((row) => String(row.id)));

  // process.stdout.write('dbArtifacts -> ' + JSON.stringify(dbArtifacts) + '\n');

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

    const versionRows = run(
      `SELECT v.version AS version, v.artifact_id AS artifact_id, a.size_bytes AS size_bytes, a.created_at AS created_at
       FROM versions v LEFT JOIN artifacts a ON a.id = v.artifact_id
       WHERE v.version != 'latest'`
    ) || [];
    process.stdout.write('versionRows -> ' + JSON.stringify(versionRows, null, 2) + '\n');

    const existingVersions = new Map(versionRows.map(row => [row.version, {
      artifactId: row.artifact_id,
      sizeBytes: row.size_bytes,
      createdAt: row.created_at
    }]));

    for (const [id, info] of diskArtifacts.entries()) {
      if (!info.version || !info.createdAt) {
        info.status = 'no_version';
        continue;
      }
      const isNewArtifact = !dbIds.has(id);
      const existingEntry = existingVersions.get(info.version);
      if (isNewArtifact && existingEntry) {
        process.stderr.write(
          `[refresh] warn: conflict version ${info.version}  - disk: ${id} (size ${info.sizeBytes} bytes, date ${info.createdAt}), db: ${existingEntry.artifactId} (size ${existingEntry.sizeBytes} bytes, date ${existingEntry.createdAt})\n`
        );
        info.status = 'version_conflict';
        continue;
      }

      if (isNewArtifact) {
        process.stderr.write(`[refresh] added artifact: ${id}\n`);
      }

      if (isNewArtifact) {
        const { versionInserted } = upsertArtifactAndVersion(
          run, 'refresh', id, info.version, info.filename, info.sizeBytes, info.createdAt
        );
        if (versionInserted) {
          existingVersions?.set(info.version, {
            artifactId: id, sizeBytes: info.sizeBytes, createdAt: info.createdAt,
          });

          added++;
          info.status = 'inserted';
          process.stderr.write(`[refresh] added artifact ${id} -> version${info.version}\n`);
        }
      } else {
        info.status = 'present';
      }
    }

    updateLatest(run);

    run('COMMIT');
  } catch (err) {
    try { run('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  }

  saveDbAtomic(db, dbPath);

  // Build artifacts output with status from diskArtifacts + skipped items
  const artifacts = [];
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

