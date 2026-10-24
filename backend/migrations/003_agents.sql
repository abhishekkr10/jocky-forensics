CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    approved_root TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    last_seen TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE agent_tasks (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at REAL NOT NULL,
    result TEXT,
    error TEXT
);
INSERT INTO schema_migrations VALUES(3);
