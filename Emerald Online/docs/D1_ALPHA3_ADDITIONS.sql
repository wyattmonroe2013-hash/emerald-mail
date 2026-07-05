CREATE TABLE IF NOT EXISTS drive_files (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  mime_type TEXT DEFAULT 'application/octet-stream',
  kind TEXT DEFAULT 'file',
  parent_id TEXT DEFAULT '',
  r2_key TEXT DEFAULT '',
  size INTEGER DEFAULT 0,
  starred INTEGER DEFAULT 0,
  trashed INTEGER DEFAULT 0,
  shared INTEGER DEFAULT 0,
  share_token TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_opened_at TEXT DEFAULT '',
  description TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_drive_owner_updated
ON drive_files (owner, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_drive_owner_parent
ON drive_files (owner, parent_id);

CREATE TABLE IF NOT EXISTS drive_activity (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  file_id TEXT,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_drive_activity_owner
ON drive_activity (owner, created_at DESC);
