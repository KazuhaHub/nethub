package main

import (
	"bytes"
	"testing"
)

func TestCertificateCommandBoundaries(t *testing.T) {
	for _, args := range [][]string{{"certificates"}, {"certificates", "unknown"}, {"certificates", "maintain-relay", "--unknown"}, {"certificates", "maintain-relay", "unexpected"}, {"certificates", "cleanup-http01", "--unknown"}, {"certificates", "cleanup-http01", "unexpected"}} {
		var out, diagnostic bytes.Buffer
		if run(args, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("invalid certificate operation accepted")
		}
	}
	var out, diagnostic bytes.Buffer
	if run([]string{"certificates", "maintain-relay", "--help"}, &out, &diagnostic) != 0 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatal("certificate help unavailable")
	}
	out.Reset()
	diagnostic.Reset()
	if run([]string{"certificates", "maintain-relay", "--directory", t.TempDir()}, &out, &diagnostic) == 0 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatal("uninitialized or unprivileged operation accepted")
	}
	out.Reset()
	diagnostic.Reset()
	if run([]string{"certificates", "cleanup-http01", "--help"}, &out, &diagnostic) != 0 || diagnostic.Len() == 0 {
		t.Fatal("cleanup help unavailable")
	}
	out.Reset()
	diagnostic.Reset()
	if run([]string{"certificates", "cleanup-http01", "--config-file", t.TempDir()}, &out, &diagnostic) != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatal("uninitialized cleanup accepted")
	}
}

func TestGUIIssuerCommandBoundaries(t *testing.T) {
	for _, args := range [][]string{{"--unknown"}, {"unexpected"}} {
		var out, diagnostic bytes.Buffer
		if runGUIIssuer(args, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("unsafe GUI issuer invocation accepted")
		}
	}
	var out, diagnostic bytes.Buffer
	if runGUIIssuer([]string{"--help"}, &out, &diagnostic) != 0 || diagnostic.Len() == 0 {
		t.Fatal("GUI issuer help unavailable")
	}
	out.Reset()
	diagnostic.Reset()
	if runGUIIssuer([]string{"--directory", t.TempDir()}, &out, &diagnostic) != 1 || out.Len() != 0 {
		t.Fatal("uninitialized GUI issuer started")
	}
}
