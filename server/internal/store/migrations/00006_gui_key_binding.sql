-- +goose Up
-- Public SPKI is admitted only as part of initial one-use enrollment. Existing
-- devices must re-enroll to gain a binding; no bearer-only first-bind endpoint.
ALTER TABLE devices ADD COLUMN gui_public_key text
 CHECK (gui_public_key IS NULL OR
  (octet_length(gui_public_key)=122 AND gui_public_key ~ '^[A-Za-z0-9_-]{121}[AQgw]$'));

-- +goose StatementBegin
CREATE FUNCTION guard_gui_key_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.gui_public_key IS DISTINCT FROM OLD.gui_public_key THEN
        RAISE EXCEPTION 'Device certificate key binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_gui_key_binding() FROM PUBLIC;
CREATE TRIGGER devices_gui_key_binding BEFORE UPDATE ON devices
 FOR EACH ROW EXECUTE FUNCTION guard_gui_key_binding();

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Certificate key bindings must be retained; restore a verified backup instead'; END $$;
