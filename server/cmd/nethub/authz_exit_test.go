package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

func TestAuthzRuntimeExitLogIsClosedJSON(t *testing.T) {
	for _, scenario := range []struct {
		err    error
		reason string
	}{
		{errors.New("private-listener-database-and-credential-error"), "service_failure"},
		{relayhook.ErrRevocationLiveness, "revocation_liveness"},
		{fmt.Errorf("private-wrapped-error: %w", relayhook.ErrRevocationLiveness), "revocation_liveness"},
	} {
		var output bytes.Buffer
		logAuthzExit(slog.New(slog.NewJSONHandler(&output, nil)), scenario.err)
		var record map[string]any
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatal("runtime exit is not a complete JSON record", err)
		}
		if len(record) != 4 || record["time"] == nil || record["level"] != "ERROR" ||
			record["msg"] != "Authz HTTP service stopped unexpectedly" || record["reason"] != scenario.reason ||
			strings.Contains(output.String(), "private-") || bytes.Count(output.Bytes(), []byte("\n")) != 1 {
			t.Fatal("runtime exit log lost its closed classification or exposed error details")
		}
	}
}
