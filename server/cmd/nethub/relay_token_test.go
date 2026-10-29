package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelayTokenHelpAndUnsafeArguments(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"relay-token", "--help"}, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "resume") || !strings.Contains(out.String(), "independent local management") {
		t.Fatal("relay token command help is incomplete")
	}
	for _, args := range [][]string{
		{}, {"unknown"}, {"rotate"}, {"rotate", "--directory", "/private-example"},
		{"resume", "--directory", "/private-example"},
		{"resume", "--directory", "/private-example", "--operation-id", "private-invalid-value"},
		{"resume", "--directory", "/private-example", "--operation-id", "12345678-1234-4123-8123-123456789abc", "--project-name", "changed"},
		{"inspect", "--directory", "/private-example", "--successor-backup", "/unrelated"},
		{"inspect", "--directory", "/private-example", "unexpected"},
	} {
		out.Reset()
		diagnostic.Reset()
		if code := runRelayToken(args, &out, &diagnostic); code != 2 || out.Len() != 0 || strings.Contains(diagnostic.String(), "private-invalid-value") {
			t.Fatal("unsafe arguments reached execution or disclosed their value")
		}
	}
}

func TestRelayTokenMissingDeploymentCreatesNothing(t *testing.T) {
	root := t.TempDir()
	directory, backup := filepath.Join(root, "missing"), filepath.Join(root, "backup")
	var out, diagnostic bytes.Buffer
	if code := runRelayToken([]string{"rotate", "--directory", directory, "--successor-backup", backup}, &out, &diagnostic); code != 1 || out.Len() != 0 {
		t.Fatal("missing deployment did not return the fixed refusal")
	}
	for _, path := range []string{directory, backup} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refused command created deployment or backup material")
		}
	}
}
