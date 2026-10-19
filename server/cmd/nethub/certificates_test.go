package main

import (
	"bytes"
	"testing"
)

func TestCertificateCommandBoundaries(t *testing.T) {
	for _, args := range [][]string{{"certificates"}, {"certificates", "unknown"}, {"certificates", "maintain-relay", "--unknown"}, {"certificates", "maintain-relay", "unexpected"}} {
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
}
