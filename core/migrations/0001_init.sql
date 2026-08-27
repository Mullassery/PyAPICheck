-- Phase 2 persistence schema: an inventory is one discovery run (one spec
-- file, or one Postman collection, at one point in time); endpoints and
-- traffic_records both hang off it. Re-running discover/report against the
-- same source creates a new inventory row rather than overwriting the
-- previous one, so history is preserved for future drift-over-time queries.

CREATE TABLE IF NOT EXISTS inventories (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    api_version TEXT NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpoints (
    id BIGSERIAL PRIMARY KEY,
    inventory_id BIGINT NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    authenticated BOOLEAN NOT NULL,
    deprecated BOOLEAN NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    endpoint_json JSONB NOT NULL,
    UNIQUE (inventory_id, method, path)
);

CREATE INDEX IF NOT EXISTS endpoints_inventory_id_idx ON endpoints (inventory_id);

CREATE TABLE IF NOT EXISTS traffic_records (
    id BIGSERIAL PRIMARY KEY,
    inventory_id BIGINT NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    observed_at TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS traffic_records_inventory_id_idx ON traffic_records (inventory_id);
