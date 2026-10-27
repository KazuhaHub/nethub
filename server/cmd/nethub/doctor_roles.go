package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/store"
)

func runRoleDoctor(config store.DatabaseConfig, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := store.OpenRole(ctx, config, "nethub_web")
	if err != nil {
		fmt.Fprintln(stderr, "Database role check unavailable; check database TLS, connectivity and the Web-role password file")
		return 1
	}
	defer db.Close()
	if err := store.CheckRuntimeRoles(ctx, db); err != nil {
		fmt.Fprintln(stderr, "Database role separation check failed; review runtime role flags and memberships, forced device RLS, schema creation and Web device identity/credential grants; restore reviewed grants through an operator migration")
		return 1
	}
	fmt.Fprintln(stdout, "Runtime database role flags, memberships and Web device identity/credential privilege separation passed in a read-only metadata snapshot")
	fmt.Fprintln(stdout, "Not checked: running container secret mounts, relay/authz loopback, recent database backup, version agreement or external network reachability")
	return 0
}
