package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseCredentialsAreNotAcceptedFromUnboundedFiles(t *testing.T) {
	for _, value := range []string{"short", "long-enough-but-with-an-embedded\nnewline-secret", string(make([]byte, 4097))} {
		file := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		config := DatabaseConfig{Host: "localhost", Port: 5432, Database: "nethub", PasswordFile: file, SSLMode: "verify-full"}
		if db, err := OpenRole(context.Background(), config, "nethub_web"); err == nil {
			db.Close()
			t.Fatal("invalid password file accepted")
		}
	}
}

func TestDatabaseRejectsUnknownRolesAndImplicitTLSDowngrade(t *testing.T) {
	for _, test := range []struct{ role, mode string }{{"postgres", "verify-full"}, {"nethub_web", "prefer"}, {"nethub_authz", ""}} {
		config := DatabaseConfig{Host: "localhost", Port: 5432, Database: "nethub", PasswordFile: "unused", SSLMode: test.mode}
		if db, err := OpenRole(context.Background(), config, test.role); err == nil {
			db.Close()
			t.Fatal("unsafe database configuration accepted")
		}
	}
}
