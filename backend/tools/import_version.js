#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import url from 'url';
import os from 'os';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import initSqlJs from 'sql.js';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--version' || a === '-v') out.version = argv[++i];
    else if (a === '--file' || a === '-f') out.file = argv[++i];
    else if (a === '--dir' || a === '-d') out.dir = argv[++i];
    else if (a === '--notes') out.notes = argv[++i];
    else if (a === '--db') out.db = argv[++i];
    else out._.push(a);
  }
  return out;
}

function usage(exitCode = 0) {
  const msg = [
    'Usage:',
    '  node backend/tools/import_version.js --version <tag> (--file <package.tar.gz> | --dir <release-dir>) [--notes "..."] [--db <path>]',
    '',
    '--file: import an already-built .tar.gz package.',
    '--dir:  build a .tar.gz from a directory (contents go to archive root) and import it.',
    '',
    'Stores the package bytes by sha256 under:',
    '  backend/data/artifacts/<sha256>',
    '',
    'And records the mapping in SQLite tables:',
    '  artifacts(id=sha256, ...), versions(version -> artifact_id)',
    ''
  ].join('\n');
  process.stderr.write(msg + '\n');
  process.exit(exitCode);
}

function buildTarFromDir(dirPath, outTarPath) {
  const st = fs.statSync(dirPath);
  if (!st.isDirectory()) throw new Error(`--dir must be a directory: ${dirPath}`);
  const proc = spawnSync('tar', ['-C', dirPath, '-czf', outTarPath, '.'], { stdio: 'pipe' });
  if (proc.error) throw proc.error;
  if (proc.status !== 0) {
    const stderr = (proc.stderr || Buffer.alloc(0)).toString('utf-8').trim();
    throw new Error(`tar failed (exit ${proc.status}): ${stderr || 'unknown error'}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) usage(0);
  if (!args.version) usage(2);
  if ((args.file ? 1 : 0) + (args.dir ? 1 : 0) !== 1) usage(2);

  const configPath = path.join(backendRoot, 'config.json');
  const fallbackConfigPath = path.join(backendRoot, 'config.example.json');
  const cfgFile = fs.existsSync(configPath) ? configPath : fallbackConfigPath;
  const config = JSON.parse(fs.readFileSync(cfgFile, 'utf-8'));

  const dbPath = path.resolve(backendRoot, args.db || config.dbPath || './data/vehicle_overseer.sqlite');
  const dataDir = path.resolve(backendRoot, 'data');
  const artifactsDir = path.resolve(dataDir, 'artifacts');
  fs.mkdirSync(artifactsDir, { recursive: true });

  let tmpDir = null;
  let packagePath = args.file;
  let filename = args.file ? path.basename(args.file) : `vehicle-overseer-device_${args.version}.tar.gz`;
  try {
    if (args.dir) {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vo-import-'));
      packagePath = path.join(tmpDir, filename);
      buildTarFromDir(args.dir, packagePath);
    }

    const buf = fs.readFileSync(packagePath);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const artifactId = sha256;
  const sizeBytes = buf.length;
  const artifactPath = path.join(artifactsDir, artifactId);
  if (!fs.existsSync(artifactPath)) {
    fs.writeFileSync(artifactPath, buf);
  }

  const SQL = await initSqlJs();
  let db;
  if (fs.existsSync(dbPath)) db = new SQL.Database(fs.readFileSync(dbPath));
  else db = new SQL.Database();
  const schemaPath = path.resolve(backendRoot, 'schema.sql');
  db.run(fs.readFileSync(schemaPath, 'utf-8'));

  const run = (sql, params = {}) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    stmt.step();
    stmt.free();
  };

  run('BEGIN');
  try {
    run(
      `INSERT OR IGNORE INTO artifacts (id, sha256, filename, size_bytes, created_at)
       VALUES ($id, $sha, $fn, $sz, datetime('now'))`,
      { $id: artifactId, $sha: sha256, $fn: filename, $sz: sizeBytes }
    );
    run(
      `INSERT OR REPLACE INTO versions (version, artifact_id, created_at, notes)
       VALUES ($v, $aid, datetime('now'), $notes)`,
      { $v: args.version, $aid: artifactId, $notes: args.notes || null }
    );
    run('COMMIT');
  } catch (err) {
    run('ROLLBACK');
    throw err;
  }

  const data = db.export();
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  {
    const tmp = `${dbPath}.tmp-${process.pid}-${Date.now()}`;
    fs.writeFileSync(tmp, Buffer.from(data));
    fs.renameSync(tmp, dbPath);
  }

  process.stdout.write(
    JSON.stringify(
      {
        ok: true,
        version: args.version,
        artifactId,
        sha256,
        filename,
        sizeBytes,
        dbPath,
        artifactPath
      },
      null,
      2
    ) + '\n'
  );
  } finally {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${err?.message || String(err)}\n`);
  process.exit(1);
});
