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

func TestAuthorityTransitionRequiresExplicitActionInputs(t *testing.T) {
	for _, args := range [][]string{
		{"activate", "--directory", "/root/deployment"},
		{"activate", "--directory", "/root/deployment", "--options-file", "/root/original.json", "--operation-id", "unexpected"},
		{"binding", "--directory", "/root/deployment", "--options-file", "/root/original.json"},
		{"resume", "--directory", "/root/deployment"},
		{"abort", "--directory", "/root/deployment", "--operation-id", "id", "--options-file", "/root/original.json"},
		{"cancel-preparation", "--operation-id", "id"},
		{"resume", "--directory", "/root/deployment", "--operation-id", "id", "extra"},
	} {
		var out, diagnostic bytes.Buffer
		if runRelayAuthority(args, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("ambiguous transition action admitted")
		}
	}
	for _, action := range []string{"binding", "activate", "resume", "abort", "cancel-preparation"} {
		var out, diagnostic bytes.Buffer
		if runRelayAuthority([]string{action, "--help"}, &out, &diagnostic) != 0 || diagnostic.Len() == 0 || out.Len() != 0 {
			t.Fatal("explicit action help unavailable")
		}
	}
}
