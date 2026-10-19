-- +goose Up
ALTER TABLE devices DROP CONSTRAINT devices_platform_check;
ALTER TABLE devices ADD CONSTRAINT devices_platform_check
    CHECK (platform COLLATE "C" ~ '^[a-z][a-z0-9-]{0,31}$');

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Platform identifiers cannot be narrowed safely; restore a verified backup instead'; END $$;
