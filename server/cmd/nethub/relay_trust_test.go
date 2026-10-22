package main

import (
	"bytes"
	"testing"
)

func TestRelayTrustCommandBoundaries(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"current", "--unknown"}, {"current", "extra"},
		{"current", "--initialize"}, {"current", "--bundle-file", "/private/public.pem"},
		{"publish", "--bundle-file", "/private/public.pem"}, {"publish", "--initialize"},
		{"publish", "--bundle-file", "/private/public.pem", "--initialize", "--expected-generation", "11111111-1111-4111-8111-111111111111"}} {
		var out, diagnostic bytes.Buffer
		if runRelayTrust(args, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("ambiguous trust invocation accepted")
		}
	}
	for _, action := range []string{"current", "publish"} {
		var out, diagnostic bytes.Buffer
		if runRelayTrust([]string{action, "--help"}, &out, &diagnostic) != 0 || diagnostic.Len() == 0 {
			t.Fatal("trust help unavailable")
		}
	}
	var out, diagnostic bytes.Buffer
	if run([]string{"certificates", "relay-trust", "current", "--directory", t.TempDir()}, &out, &diagnostic) != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatal("uninitialized or unprivileged publication host accepted")
	}
}
