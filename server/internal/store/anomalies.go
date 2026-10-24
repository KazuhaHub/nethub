package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
)

type anomalyDevice struct {
	tenant, id, subdomain string
	revoked, clusterHint  bool
}

func validateAnomalyRoutes(routes []relaystate.ObservedRoute) error {
	if len(routes) > relaystate.MaxProxies {
		return relaystate.ErrAnomalySample
	}
	keys := make(map[string]bool, len(routes))
	devices := make(map[string]bool, len(routes))
	for _, route := range routes {
		if !route.Valid() || keys[route.ProxyKey] || route.DeviceID != "" && devices[route.DeviceID] {
			return relaystate.ErrAnomalySample
		}
		keys[route.ProxyKey] = true
		if route.DeviceID != "" {
			devices[route.DeviceID] = true
		}
	}
	return nil
}

func anomalyTenants(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1025`)
	if err != nil {
		return nil, relaystate.ErrStorage
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenant string
		if rows.Scan(&tenant) != nil {
			return nil, relaystate.ErrStorage
		}
		tenants = append(tenants, tenant)
	}
	if rows.Err() != nil || len(tenants) == 0 || len(tenants) > 1024 {
		return nil, relaystate.ErrStorage
	}
	return tenants, nil
}

// Tenant and assignment authority comes only from the scoped device rows.
// A candidate UUID in an admin response does not establish either identity.
func currentAnomalies(ctx context.Context, tx *sql.Tx, routes []relaystate.ObservedRoute) ([]relaystate.Anomaly, []string, map[string]anomalyDevice, error) {
	if err := validateAnomalyRoutes(routes); err != nil {
		return nil, nil, nil, err
	}
	tenants, err := anomalyTenants(ctx, tx)
	if err != nil {
		return nil, nil, nil, err
	}
	if routes == nil {
		routes = []relaystate.ObservedRoute{}
	}
	encoded, err := json.Marshal(routes)
	if err != nil {
		return nil, nil, nil, relaystate.ErrAnomalySample
	}
	records := make(map[string]anomalyDevice, len(routes))
	statement := `SELECT d.tenant_id,d.id,d.subdomain,d.revoked,(d.cluster_hint IS NOT NULL AND d.cluster_hint<>''),r.proxy_key
FROM devices d JOIN jsonb_to_recordset($1::jsonb) AS r(device_id text,subdomain text,proxy_key text)
  ON d.id=nullif(r.device_id,'')::uuid
WHERE d.tenant_id=$2 ORDER BY d.id`
	for _, tenant := range tenants {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return nil, nil, nil, relaystate.ErrStorage
		}
		rows, err := tx.QueryContext(ctx, statement, string(encoded), tenant)
		if err != nil {
			return nil, nil, nil, relaystate.ErrStorage
		}
		for rows.Next() {
			var record anomalyDevice
			var key string
			if rows.Scan(&record.tenant, &record.id, &record.subdomain, &record.revoked, &record.clusterHint, &key) != nil {
				rows.Close()
				return nil, nil, nil, relaystate.ErrStorage
			}
			if _, duplicate := records[key]; duplicate {
				rows.Close()
				return nil, nil, nil, relaystate.ErrAnomalySample
			}
			records[key] = record
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, nil, relaystate.ErrStorage
		}
	}
	findings := make([]relaystate.Anomaly, 0, len(routes))
	for _, route := range routes {
		record, known := records[route.ProxyKey]
		if !known {
			findings = append(findings, relaystate.Anomaly{Kind: relaystate.UnknownProxy, ProxyKey: route.ProxyKey})
			continue
		}
		kind := relaystate.AnomalyKind("")
		if record.revoked {
			kind = relaystate.RevokedOnline
		} else if record.subdomain != route.Subdomain {
			kind = relaystate.DomainMismatch
		}
		if kind != "" {
			findings = append(findings, relaystate.Anomaly{Kind: kind, TenantID: record.tenant, DeviceID: record.id, ProxyKey: route.ProxyKey})
		}
	}
	return findings, tenants, records, nil
}

func (s *ObservationStore) Inspect(ctx context.Context, routes []relaystate.ObservedRoute) ([]relaystate.Anomaly, error) {
	if s == nil || s.DB == nil {
		return nil, relaystate.ErrStorage
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, relaystate.ErrStorage
	}
	defer tx.Rollback()
	findings, _, _, err := currentAnomalies(ctx, tx, routes)
	if err != nil {
		return nil, err
	}
	if tx.Commit() != nil {
		return nil, relaystate.ErrStorage
	}
	return findings, nil
}
