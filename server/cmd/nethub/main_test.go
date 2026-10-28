package main

import (
	"bytes"
	"testing"
)

func TestOperationsRequireImplementationOrConfiguration(t *testing.T) {
	for _, command := range []string{"web", "authz", "migrate", "init", "doctor", "admin", "backup"} {
		t.Run(command, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if status := run([]string{command}, &out, &diagnostic); status == 0 || out.Len() != 0 || diagnostic.Len() == 0 {
				t.Fatalf("unexpected command result: status=%d stdout=%q stderr=%q", status, out.String(), diagnostic.String())
			}
		})
	}
}
