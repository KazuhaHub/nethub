-- +goose Up
ALTER TABLE identity_providers
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    ADD COLUMN deleted_at timestamptz,
    ADD CONSTRAINT identity_provider_deleted_disabled CHECK (deleted_at IS NULL OR NOT enabled);

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup before reverting provider lifecycle history'; END $$;
