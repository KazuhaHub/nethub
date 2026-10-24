-- +goose Up
CREATE INDEX devices_revocation_snapshot ON devices(tenant_id,id) WHERE revoked;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup before reverting the revocation snapshot migration'; END $$;
