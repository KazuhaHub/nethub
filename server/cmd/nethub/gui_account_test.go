package main

import (
	"bytes"
	"testing"
)

func TestGUIAccountCommandUsageAndUninitializedRefusal(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"initialize", "--unknown"}, {"terms", "unexpected"}} {
		var out, diagnostic bytes.Buffer
		if runGUIAccount(args, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("invalid account command accepted")
		}
	}
	for _, args := range [][]string{{"--help"}, {"register", "--help"}} {
		var out, diagnostic bytes.Buffer
		if runGUIAccount(args, &out, &diagnostic) != 0 || out.Len() != 0 || diagnostic.Len() == 0 {
			t.Fatal("account help unavailable")
		}
	}
	var out, diagnostic bytes.Buffer
	if runGUIAccount([]string{"initialize", "--directory", t.TempDir()}, &out, &diagnostic) != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatal("uninitialized deployment accepted")
	}
}
