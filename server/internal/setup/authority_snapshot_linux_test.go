package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthoritySnapshotPrivateReadsAreBoundedAndIndependent(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private fixture")
	}
	path := filepath.Join(root, "material")
	payload := bytes.Repeat([]byte("x"), 128)
	if os.WriteFile(path, payload, 0600) != nil {
		t.Fatal("private file fixture")
	}
	raw, err := authorityRead(path, os.Geteuid(), 128)
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("bounded private read", err)
	}
	if _, err := authorityRead(path, os.Geteuid(), 127); err == nil {
		t.Fatal("oversized private file admitted")
	}
	alias := filepath.Join(root, "alias")
	if os.Link(path, alias) != nil {
		t.Fatal("hardlink fixture")
	}
	if _, err := authorityRead(path, os.Geteuid(), 128); err == nil {
		t.Fatal("aliased private file admitted")
	}
	if os.Remove(alias) != nil || os.Symlink(path, alias) != nil {
		t.Fatal("symlink fixture")
	}
	if _, err := authorityRead(alias, os.Geteuid(), 128); err == nil {
		t.Fatal("symlink private file admitted")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("mode fixture")
	}
	if _, err := authorityRead(path, os.Geteuid(), 128); err == nil {
		t.Fatal("readable private file admitted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, payload) {
		t.Fatal("refused reads changed material")
	}
}
