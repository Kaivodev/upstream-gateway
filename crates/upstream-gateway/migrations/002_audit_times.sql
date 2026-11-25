-- Version 1 did not record these times. Preserve unknown historical times as NULL.
ALTER TABLE operations ADD COLUMN created_at timestamptz, ADD COLUMN completed_at timestamptz;
ALTER TABLE operations ALTER COLUMN created_at SET DEFAULT clock_timestamp();
ALTER TABLE attempts ADD COLUMN dispatched_at timestamptz, ADD COLUMN received_at timestamptz;
ALTER TABLE attempts ALTER COLUMN dispatched_at SET DEFAULT clock_timestamp();
