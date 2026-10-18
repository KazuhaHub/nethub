package store

import (
	"context"
	"database/sql"
)

type Device struct {
	ID, OwnerID, Label, Subdomain string
	Revoked                       bool
}

// ListDevices derives authorization from the enabled actor, not a caller role flag.
func ListDevices(ctx context.Context, db *sql.DB, tenant, actor string) ([]Device, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT d.id, d.owner_user_id, d.label, d.subdomain, d.revoked
        FROM devices d JOIN users u ON u.tenant_id = d.tenant_id
        WHERE u.id = $1 AND u.disabled_at IS NULL AND (u.role = 'admin' OR d.owner_user_id = u.id)
        ORDER BY d.enrolled_at, d.id`, actor)
	if err != nil {
		return nil, err
	}
	devices := []Device{}
	for rows.Next() {
		var device Device
		if err := rows.Scan(&device.ID, &device.OwnerID, &device.Label, &device.Subdomain, &device.Revoked); err != nil {
			rows.Close()
			return nil, err
		}
		devices = append(devices, device)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return devices, tx.Commit()
}
