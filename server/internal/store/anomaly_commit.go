package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
)

var _ relaystate.AnomalyRepository = (*ObservationStore)(nil)

type incidentInput struct {
	DeviceID string                 `json:"device_id"`
	Kind     relaystate.AnomalyKind `json:"kind"`
	ProxyKey string                 `json:"proxy_key"`
	Response string                 `json:"response,omitempty"`
}

type incidentDecision struct {
	ID       string                 `json:"incident_id"`
	DeviceID string                 `json:"device_id"`
	Kind     relaystate.AnomalyKind `json:"kind"`
	Response string                 `json:"response"`
}

func anomalySet(values []relaystate.Anomaly) (map[relaystate.Anomaly]bool, error) {
	if len(values) > relaystate.MaxProxies {
		return nil, relaystate.ErrAnomalySample
	}
	result := make(map[relaystate.Anomaly]bool, len(values))
	for _, value := range values {
		if !value.Valid() || result[value] {
			return nil, relaystate.ErrAnomalySample
		}
		result[value] = true
	}
	return result, nil
}

func validateConfirmations(expected []relaystate.Anomaly, batch []relaystate.AnomalyConfirmation) error {
	allowed, err := anomalySet(expected)
	if err != nil || len(batch) > relaystate.MaxProxies {
		return relaystate.ErrAnomalySample
	}
	seen := make(map[relaystate.Anomaly]bool, len(batch))
	for _, confirmation := range batch {
		if !allowed[confirmation.Anomaly] || seen[confirmation.Anomaly] || confirmation.Token == 0 {
			return relaystate.ErrAnomalySample
		}
		seen[confirmation.Anomaly] = true
	}
	return nil
}

func lockAnomalyDevices(ctx context.Context, tx *sql.Tx, tenants []string, expected []relaystate.Anomaly) error {
	type target struct {
		TenantID string `json:"tenant_id"`
		DeviceID string `json:"device_id"`
	}
	targets := make([]target, 0, len(expected))
	for _, finding := range expected {
		if finding.DeviceID != "" {
			targets = append(targets, target{finding.TenantID, finding.DeviceID})
		}
	}
	if len(targets) == 0 {
		return nil
	}
	encoded, _ := json.Marshal(targets)
	for _, tenant := range tenants {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return relaystate.ErrStorage
		}
		// Normal display observations must not acquire device locks. Busy anomaly
		// targets skip this attempt instead of holding up connection admissions.
		rows, err := tx.QueryContext(ctx, `SELECT d.id FROM devices d
JOIN jsonb_to_recordset($1::jsonb) AS target(tenant_id uuid,device_id uuid)
  ON d.tenant_id=target.tenant_id AND d.id=target.device_id
WHERE d.tenant_id=$2 ORDER BY d.id FOR UPDATE OF d NOWAIT`, string(encoded), tenant)
		if err != nil {
			return relaystate.ErrStorage
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return relaystate.ErrStorage
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return relaystate.ErrStorage
		}
	}
	return nil
}

func sameAnomalies(left, right []relaystate.Anomaly) bool {
	a, err := anomalySet(left)
	if err != nil || len(left) != len(right) {
		return false
	}
	b, err := anomalySet(right)
	if err != nil {
		return false
	}
	for value := range b {
		if !a[value] {
			return false
		}
	}
	return true
}

func tenantIncidentInputs(tenant string, findings []relaystate.Anomaly) []incidentInput {
	result := make([]incidentInput, 0, len(findings))
	for _, finding := range findings {
		if finding.Kind == relaystate.UnknownProxy || finding.TenantID == tenant {
			result = append(result, incidentInput{DeviceID: finding.DeviceID, Kind: finding.Kind, ProxyKey: finding.ProxyKey})
		}
	}
	return result
}

func persistTenantAnomalies(ctx context.Context, tx *sql.Tx, tenant string, findings []relaystate.Anomaly,
	batch []relaystate.AnomalyConfirmation, devices map[string]anomalyDevice) error {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
		return relaystate.ErrStorage
	}
	current, _ := json.Marshal(tenantIncidentInputs(tenant, findings))
	resolved, err := tx.ExecContext(ctx, `UPDATE relay_anomaly_incidents i SET resolved_at=clock_timestamp()
WHERE i.tenant_id=$1 AND i.resolved_at IS NULL AND NOT EXISTS (
 SELECT FROM jsonb_to_recordset($2::jsonb) AS r(device_id text,kind text,proxy_key text)
 WHERE i.kind=r.kind AND i.proxy_key=r.proxy_key AND coalesce(i.device_id::text,'')=r.device_id)`, tenant, string(current))
	if err != nil {
		return relaystate.ErrStorage
	}
	resolvedCount, err := resolved.RowsAffected()
	if err != nil {
		return relaystate.ErrStorage
	}
	if _, err := tx.ExecContext(ctx, `UPDATE relay_anomaly_incidents i SET last_observed_at=clock_timestamp()
WHERE i.tenant_id=$1 AND i.resolved_at IS NULL AND EXISTS (
 SELECT FROM jsonb_to_recordset($2::jsonb) AS r(device_id text,kind text,proxy_key text)
 WHERE i.kind=r.kind AND i.proxy_key=r.proxy_key AND coalesce(i.device_id::text,'')=r.device_id)`, tenant, string(current)); err != nil {
		return relaystate.ErrStorage
	}
	inputs := make([]incidentInput, 0, len(batch))
	for _, confirmation := range batch {
		if confirmation.Kind != relaystate.UnknownProxy && confirmation.TenantID != tenant {
			continue
		}
		response := "alarm_only"
		device := devices[confirmation.ProxyKey]
		if !confirmation.AlarmOnly && !device.clusterHint {
			if confirmation.Kind == relaystate.DomainMismatch {
				response = "revoked"
			}
			if confirmation.Kind == relaystate.RevokedOnline {
				response = "already_revoked"
			}
		}
		inputs = append(inputs, incidentInput{DeviceID: confirmation.DeviceID, Kind: confirmation.Kind, ProxyKey: confirmation.ProxyKey, Response: response})
	}
	encoded, _ := json.Marshal(inputs)
	rows, err := tx.QueryContext(ctx, `INSERT INTO relay_anomaly_incidents(tenant_id,device_id,kind,proxy_key,response)
SELECT $1,nullif(r.device_id,'')::uuid,r.kind,r.proxy_key,r.response
FROM jsonb_to_recordset($2::jsonb) AS r(device_id text,kind text,proxy_key text,response text)
ON CONFLICT DO NOTHING RETURNING id,coalesce(device_id::text,''),kind,response`, tenant, string(encoded))
	if err != nil {
		return relaystate.ErrStorage
	}
	decisions := make([]incidentDecision, 0, len(inputs))
	unknownCount := 0
	revoke := make([]string, 0, len(inputs))
	for rows.Next() {
		var decision incidentDecision
		if rows.Scan(&decision.ID, &decision.DeviceID, &decision.Kind, &decision.Response) != nil {
			rows.Close()
			return relaystate.ErrStorage
		}
		if decision.Kind == relaystate.UnknownProxy {
			unknownCount++
		} else {
			decisions = append(decisions, decision)
		}
		if decision.Response == "revoked" {
			revoke = append(revoke, decision.DeviceID)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return relaystate.ErrStorage
	}
	if len(revoke) > 0 {
		encoded, _ = json.Marshal(revoke)
		updated, err := tx.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp(),revoked_by_user_id=NULL
WHERE tenant_id=$1 AND NOT revoked AND id IN (SELECT value::uuid FROM jsonb_array_elements_text($2::jsonb))`, tenant, string(encoded))
		if err != nil {
			return relaystate.ErrStorage
		}
		count, err := updated.RowsAffected()
		if err != nil {
			return relaystate.ErrStorage
		}
		if count != int64(len(revoke)) {
			return relaystate.ErrAnomalyChanged
		}
	}
	if len(decisions) > 0 || unknownCount > 0 || resolvedCount > 0 {
		// One bounded tenant audit records the batch. Unknown routes expose only
		// a deployment-wide count, never a name, digest or guessed device owner.
		payload, _ := json.Marshal(map[string]any{"decisions": decisions, "unknown_confirmed": unknownCount, "resolved": resolvedCount})
		if _, err := tx.ExecContext(ctx, `SELECT append_audit('system',NULL,'relay.anomaly_decisions',NULL,$1::jsonb)`, string(payload)); err != nil {
			return relaystate.ErrStorage
		}
	}
	return nil
}

func (s *ObservationStore) Commit(ctx context.Context, routes []relaystate.ObservedRoute, expected []relaystate.Anomaly, batch []relaystate.AnomalyConfirmation) error {
	if s == nil || s.DB == nil {
		return relaystate.ErrStorage
	}
	if err := validateAnomalyRoutes(routes); err != nil {
		return err
	}
	if err := validateConfirmations(expected, batch); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return relaystate.ErrStorage
	}
	defer tx.Rollback()
	tenants, err := anomalyTenants(ctx, tx)
	if err != nil {
		return err
	}
	if err = lockAnomalyDevices(ctx, tx, tenants, expected); err != nil {
		return err
	}
	current, currentTenants, devices, err := currentAnomalies(ctx, tx, routes)
	if err != nil {
		return err
	}
	if !slices.Equal(tenants, currentTenants) || !sameAnomalies(expected, current) {
		return relaystate.ErrAnomalyChanged
	}
	for _, tenant := range tenants {
		if err = persistTenantAnomalies(ctx, tx, tenant, current, batch, devices); err != nil {
			return err
		}
	}
	if tx.Commit() != nil {
		return relaystate.ErrStorage
	}
	return nil
}
