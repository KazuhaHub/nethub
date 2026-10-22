package main

import (
	"bytes"
	"testing"
)

func TestRelayAuthorityCommandRefusesImplicitActivation(t *testing.T) {
	for _, args := range [][]string{nil, {"activate"}, {"prepare", "--unknown"}, {"prepare", "extra"}} {
		var out, diagnostic bytes.Buffer
		if runRelayAuthority(args, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("invalid authority command admitted")
		}
	}
	for _, action := range []string{"prepare", "inspect", "backup", "verify-backup", "acknowledge-backup", "verify-custody"} {
		var out, diagnostic bytes.Buffer
		if runRelayAuthority([]string{action, "--help"}, &out, &diagnostic) != 0 || diagnostic.Len() == 0 {
			t.Fatal("offline authority help unavailable")
		}
		out.Reset()
		diagnostic.Reset()
		if run([]string{"certificates", "relay-authority", action, "--directory", t.TempDir()}, &out, &diagnostic) != 1 || out.Len() != 0 {
			t.Fatal("uninitialized authority command admitted")
		}
	}
}
