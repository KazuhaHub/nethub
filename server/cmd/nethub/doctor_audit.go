package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/store"
)

type auditDoctorOptions struct {
	Database   store.DatabaseConfig
	LegacyZone string
	Timeout    time.Duration
}

func runAuditDoctor(options auditDoctorOptions, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()
	db, err := store.OpenRole(ctx, options.Database, "nethub_web")
	if err != nil {
		fmt.Fprintln(stderr, "Audit database connection failed; check TLS, connectivity and the Web-role password file")
		return 1
	}
	defer db.Close()
	tenant, err := store.SoleTenant(ctx, db)
	if err != nil {
		fmt.Fprintln(stderr, "Audit check requires migrated tables and exactly one deployment tenant")
		return 1
	}
	result, err := store.VerifyAuditChain(ctx, db, tenant, options.LegacyZone)
	if errors.Is(err, store.ErrAuditChainInvalid) {
		fmt.Fprintln(stderr, "Audit chain could not be verified; preserve a database snapshot and investigate the legacy writer timezone, record size and stored history; no repair was performed")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "Audit verification unavailable; check migrations, read permissions, timeout and the legacy timezone name; no history was changed")
		return 1
	}
	fmt.Fprintf(stdout, "Audit chain verified: entries=%d, legacy=%d, read-only snapshot\n", result.Entries, result.LegacyEntries)
	fmt.Fprintln(stdout, "Linked history is not proof against hostile rewriting or tail truncation")
	return 0
}
