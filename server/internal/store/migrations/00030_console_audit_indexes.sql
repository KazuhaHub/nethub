-- +goose Up
CREATE INDEX audit_log_target_lookup ON audit_log (tenant_id, target_device_id, action, actor_type, actor_id);
CREATE INDEX audit_log_actor_page ON audit_log (tenant_id, actor_id, sequence DESC);
CREATE INDEX audit_log_action_page ON audit_log (tenant_id, action, sequence DESC);

-- +goose Down
DROP INDEX audit_log_action_page;
DROP INDEX audit_log_actor_page;
DROP INDEX audit_log_target_lookup;
