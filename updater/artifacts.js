#!/usr/bin/env node

// Artifact tooling.
//
// Goals:
// - `make`: create a .tar.gz artifact from a directory (or accept an existing tar.gz) WITHOUT touching the backend DB.
// - `import`: copy artifact bytes into backend data/artifacts/<sha256> and record version->artifact mapping in SQLite.
//
// Typical flows:
// - Local build:   node updater/artifacts.js make ./release-dir --version v0.1.0 --out ./artifact.tar.gz
// - Local import:  node updater/artifacts.js import ./artifact.tar.gz --version v0.1.0
// - Combined:      node updater/artifacts.js make ./release-dir --version v0.1.0 --import
// - Shorthand:     node updater/artifacts.js ./release-dir --version v0.1.0   (implies `make`)

import fs from 'fs';
import path from 'path';
import url from 'url';
import os from 'os';
import crypto from 'crypto';
import { spawnSync } from 'child_process';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const backendRoot = path.join(repoRoot, 'backend');
const updaterRoot = path.resolve(__dirname);
const deviceServiceRoot = path.join(repoRoot, 'device-service');

const SYSTEMD_UNITS = ['updater.service', 'updater.timer'];
const UPDATE_SCRIPT = 'update.sh';
const UPDATER_SETUP_SCRIPT = 'updater-setup.sh';
const SERVICE_SETUP_SCRIPT = 'service-setup.sh';

const DEFAULT_UPDATE_SH = `#!/bin/sh
set -eu

log() { printf '[update.sh] %s\n' "$*" >&2; }

APP_DIR="$(cd "$(dirname "$0")" && pwd)"

run_if_present() {
  p="$1"
  if [ ! -f "$p" ]; then
    return 0
  fi
  log "run: $p"
  if [ -x "$p" ]; then
    "$p"
  else
    sh "$p"
  fi
}

run_if_present "$APP_DIR/updater/${UPDATER_SETUP_SCRIPT}"
run_if_present "$APP_DIR/device-service/${SERVICE_SETUP_SCRIPT}"

exit 0
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--version' || a === '-v') out.version = argv[++i];
    else if (a === '--notes') out.notes = argv[++i];
    else if (a === '--update-script') out.updateScript = argv[++i];
    else if (a === '--out' || a === '-o') out.out = argv[++i];
    else if (a === '--import') out.import = true;
    else if (a === '--backend-root') out.backendRoot = argv[++i];
    else if (a === '--db') out.db = argv[++i];
    else if (a === '--artifacts-dir') out.artifactsDir = argv[++i];
    else out._.push(a);
  }
  return out;
}

function usage(exitCode = 0) {
  const msg = [
    'Usage:',
    '  node updater/artifacts.js make <path> [--version <tag>] [--out <artifact.tar.gz>] [--notes "..."] [--update-script <path>] [--import]',
    '  node updater/artifacts.js import <artifact.tar.gz> [--version <tag>] [--notes "..."]',
    '  node updater/artifacts.js <path> [--version <tag>] [--out <artifact.tar.gz>] [--update-script <path>] [--import]    (shorthand for `make`)',
    '',
    'Notes:',
    '  - `make` only creates a tar.gz. It does NOT touch SQLite.',
    '  - `import` copies bytes into backend data/ and writes SQLite rows (artifacts + versions).',
    '  - `--import` on `make` runs import immediately after build using the repo backend/ by default.',
    '  - `--update-script` lets you provide a custom update.sh; otherwise a default update.sh is injected if missing.',
    '  - If `--version` is omitted on import, the importer tries to read VERSION from inside the tarball (requires `tar`).',
    '',
    'Defaults (repo layout):',
    `  --backend-root ${backendRoot}`,
    '  DB:          <backend-root>/data/vehicle_overseer.sqlite (or backend/config.json dbPath)',
    '  Artifacts:   <backend-root>/data/artifacts/',
    '',
  ].join('\n');
  process.stderr.write(msg + '\n');
  process.exit(exitCode);
}

function shQuote(s) {
  return `'${String(s).replace(/'/g, `'"'"'`)}'`;
}

function buildTarFromDir(dirPath, outTarPath) {
  const st = fs.statSync(dirPath);
  if (!st.isDirectory()) throw new Error(`input must be a directory: ${dirPath}`);
  const proc = spawnSync('tar', ['-C', dirPath, '-czf', outTarPath, '.'], { stdio: 'pipe' });
  if (proc.error) throw proc.error;
  if (proc.status !== 0) {
    const stderr = (proc.stderr || Buffer.alloc(0)).toString('utf-8').trim();
    throw new Error(`tar failed (exit ${proc.status}): ${stderr || 'unknown error'}`);
  }
}

function ensureSystemdUnits(stagingDir) {
  const srcDir = path.join(updaterRoot, 'systemd');
  if (!fs.existsSync(srcDir)) return;
  const systemdDir = path.join(stagingDir, 'systemd');
  for (const name of SYSTEMD_UNITS) {
    const rootCandidate = path.join(stagingDir, name);
    const systemdCandidate = path.join(systemdDir, name);
    if (fs.existsSync(rootCandidate) || fs.existsSync(systemdCandidate)) continue;
    fs.mkdirSync(systemdDir, { recursive: true });
    fs.copyFileSync(path.join(srcDir, name), systemdCandidate);
    process.stderr.write(`[artifacts] injected default systemd template: systemd/${name}\n`);
  }
}

function ensureUpdateScript(stagingDir, overridePath) {
  const scriptPath = path.join(stagingDir, UPDATE_SCRIPT);
  if (overridePath) {
    const src = path.resolve(overridePath);
    if (!fs.existsSync(src) || !fs.statSync(src).isFile()) {
      throw new Error(`--update-script not found: ${src}`);
    }
    fs.copyFileSync(src, scriptPath);
    fs.chmodSync(scriptPath, 0o755);
    process.stderr.write(`[artifacts] set ${UPDATE_SCRIPT} from --update-script (${src})\n`);
    return;
  }

  if (fs.existsSync(scriptPath)) return;
  fs.writeFileSync(scriptPath, DEFAULT_UPDATE_SH, 'utf-8');
  fs.chmodSync(scriptPath, 0o755);
  process.stderr.write(`[artifacts] injected default ${UPDATE_SCRIPT} (no update.sh provided)\n`);
}

function ensureUpdaterSetupScript(stagingDir) {
  const dstDir = path.join(stagingDir, 'updater');
  fs.mkdirSync(dstDir, { recursive: true });

  const dst = path.join(dstDir, UPDATER_SETUP_SCRIPT);
  if (fs.existsSync(dst)) return;

  const src = path.join(updaterRoot, UPDATER_SETUP_SCRIPT);
  if (!fs.existsSync(src)) {
    throw new Error(`missing template: ${src}`);
  }
  fs.copyFileSync(src, dst);
  fs.chmodSync(dst, 0o755);
  process.stderr.write(`[artifacts] injected default updater/${UPDATER_SETUP_SCRIPT}\n`);
}

function ensureDeviceServicePayload(stagingDir) {
  // The runtime contract is:
  // - update.sh calls app/device-service/service-setup.sh
  // - device-service/service-setup.sh installs /etc/systemd/system/vehicle-overseer.service
  // - systemd unit runs /opt/vehicle-overseer/app/service.py
  // Artifact-maker makes this easy by injecting these defaults if missing.

  const dstDeviceDir = path.join(stagingDir, 'device-service');
  fs.mkdirSync(dstDeviceDir, { recursive: true });

  const srcSetup = path.join(deviceServiceRoot, SERVICE_SETUP_SCRIPT);
  const dstSetup = path.join(dstDeviceDir, SERVICE_SETUP_SCRIPT);
  if (!fs.existsSync(dstSetup)) {
    fs.copyFileSync(srcSetup, dstSetup);
    fs.chmodSync(dstSetup, 0o755);
    process.stderr.write(`[artifacts] injected default device-service/${SERVICE_SETUP_SCRIPT}\n`);
  }

  const srcUnit = path.join(deviceServiceRoot, 'systemd', 'vehicle-overseer.service');
  const dstUnitDir = path.join(dstDeviceDir, 'systemd');
  const dstUnit = path.join(dstUnitDir, 'vehicle-overseer.service');
  if (!fs.existsSync(dstUnit)) {
    fs.mkdirSync(dstUnitDir, { recursive: true });
    fs.copyFileSync(srcUnit, dstUnit);
    process.stderr.write('[artifacts] injected default device-service/systemd/vehicle-overseer.service\n');
  }

  const srcService = path.join(deviceServiceRoot, 'service.py');
  const dstService = path.join(stagingDir, 'service.py');
  if (!fs.existsSync(dstService)) {
    fs.copyFileSync(srcService, dstService);
    fs.chmodSync(dstService, 0o755);
    process.stderr.write('[artifacts] injected default service.py\n');
  }
}

function sha256FileHex(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function defaultArtifactOutPath(version) {
  if (!version) return path.resolve('artifact.tar.gz');
  const safeV = String(version).replace(/[^A-Za-z0-9._-]/g, '_');
  return path.resolve(`artifact_${safeV}.tar.gz`);
}

async function importViaBackendCli({ backendRootPath, artifactPath, version, notes, db, artifactsDir }) {
  // Import uses backend code (so schema/db defaults are consistent).
  // This requires node for the tooling path; the SEA binary has its own `artifacts import` mode.
  const cliPath = path.join(backendRootPath, 'src', 'artifacts_cli.js');
  if (!fs.existsSync(cliPath)) {
    throw new Error(`backend artifacts CLI not found: ${cliPath}`);
  }
  const nodeArgs = [
    cliPath,
    'import',
    artifactPath,
    ...(version ? ['--version', version] : []),
    ...(notes ? ['--notes', notes] : []),
    ...(db ? ['--db', db] : []),
    ...(artifactsDir ? ['--artifacts-dir', artifactsDir] : []),
  ];
  const proc = spawnSync(process.execPath, nodeArgs, { stdio: 'inherit' });
  if (proc.error) throw proc.error;
  if (proc.status !== 0) {
    throw new Error(`import failed (exit ${proc.status})`);
  }
}

async function cmdMake(args) {
  const inputPath = args._[0];
  if (!inputPath) usage(2);

  const resolvedInput = path.resolve(inputPath);
  if (!fs.existsSync(resolvedInput)) {
    throw new Error(`input path not found: ${resolvedInput}`);
  }

  const st = fs.statSync(resolvedInput);
  const outPath = path.resolve(args.out || defaultArtifactOutPath(args.version));

  let tmpDir = null;
  try {
    if (st.isDirectory()) {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vo-artifact-'));
      const stagingDir = path.join(tmpDir, 'staging');
      fs.mkdirSync(stagingDir, { recursive: true });
      for (const entry of fs.readdirSync(resolvedInput)) {
        fs.cpSync(path.join(resolvedInput, entry), path.join(stagingDir, entry), { recursive: true });
      }
      ensureSystemdUnits(stagingDir);
      ensureUpdateScript(stagingDir, args.updateScript);
      ensureUpdaterSetupScript(stagingDir);
      ensureDeviceServicePayload(stagingDir);
      buildTarFromDir(stagingDir, outPath);
    } else if (st.isFile()) {
      // If the input is already a tarball, just copy it to the requested output.
      if (path.resolve(resolvedInput) !== path.resolve(outPath)) {
        fs.copyFileSync(resolvedInput, outPath);
      }
    } else {
      throw new Error(`unsupported input type: ${resolvedInput}`);
    }

    const sha256 = sha256FileHex(outPath);
    const sizeBytes = fs.statSync(outPath).size;
    process.stdout.write(JSON.stringify({ ok: true, mode: 'make', version: args.version, outPath, sha256, sizeBytes }, null, 2) + '\n');

    if (args.import) {
      const backendRootPath = path.resolve(args.backendRoot || backendRoot);
      await importViaBackendCli({
        backendRootPath,
        artifactPath: outPath,
        version: args.version,
        notes: args.notes,
        db: args.db,
        artifactsDir: args.artifactsDir,
      });
    }
  } finally {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function cmdImport(args) {
  if (!args._.length) usage(2);
  const backendRootPath = path.resolve(args.backendRoot || backendRoot);
  for (const artifactPath of args._) {
    const resolvedArtifact = path.resolve(artifactPath);
    await importViaBackendCli({
      backendRootPath,
      artifactPath: resolvedArtifact,
      version: args.version,
      notes: args.notes,
      db: args.db,
      artifactsDir: args.artifactsDir,
    });
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const inferredCmd = (argv[0] && !['make', 'import', '--help', '-h'].includes(argv[0]) && !argv[0].startsWith('-')) ? 'make' : null;

  const cmd = inferredCmd ? 'make' : argv[0];
  const rest = inferredCmd ? argv : argv.slice(1);

  const args = parseArgs(rest);
  if (args.help) usage(0);

  if (cmd === 'make') return cmdMake(args);
  if (cmd === 'import') return cmdImport(args);
  usage(2);
}

main().catch((err) => {
  process.stderr.write(`error: ${err?.message || String(err)}\n`);
  process.exit(1);
});
