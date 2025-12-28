PRAGMA foreign_keys = OFF;

-- Minimal persistent backend state:
-- - Update artifacts and version tags
-- - Per-device desired/target version
-- - Per-device transfer keys
-- - Bootstrap tokens (one-time and dev multi-use)

-- Artifact store: server stores package bytes by content hash (artifact id).
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, -- artifact id (currently: sha256 hex)
  sha256 TEXT NOT NULL UNIQUE,
  filename TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Version tags mapped to an artifact id (package file, e.g. .tar.gz).
CREATE TABLE IF NOT EXISTS versions (
  version TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  notes TEXT,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

-- Per-device desired target version (NULL = newest available).
CREATE TABLE IF NOT EXISTS device_targets (
  vin TEXT PRIMARY KEY,
  desired_version TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Optional per-device artifact transfer key (base64, 32 bytes). Used only for in-transfer encryption.
CREATE TABLE IF NOT EXISTS device_keys (
  device_uid TEXT PRIMARY KEY,
  key_id TEXT,
  key_b64 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One-time bootstrap tokens (and optional dev multi-use tokens) for provisioning device_keys.
CREATE TABLE IF NOT EXISTS bootstrap_tokens (
  token TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'one-time', -- one-time | dev
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  used_at TEXT
);
