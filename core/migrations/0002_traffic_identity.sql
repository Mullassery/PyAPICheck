-- Phase 4 needs to attribute traffic to a caller identity for per-identity
-- baselining; not every log line carries one (see traffic.rs), so this is
-- nullable, matching TrafficRecord.identity: Option<String>.
ALTER TABLE traffic_records ADD COLUMN IF NOT EXISTS identity TEXT;

CREATE INDEX IF NOT EXISTS traffic_records_identity_idx ON traffic_records (inventory_id, identity);
