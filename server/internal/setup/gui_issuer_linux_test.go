package setup

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestGUIIssuerDatabaseBindingRejectsUnrelatedAndWritableSecrets(t *testing.T) {
	directory := t.TempDir()
	project := "nethub-fixture"
	type mount struct {
		Type, Source, Destination, Name string
		RW                              bool
	}
	value := struct {
		WorkingDir string `json:"working_dir"`
		Mounts     []mount
	}{directory, []mount{
		{Type: "volume", Name: project + "_database", Destination: "/var/lib/postgresql/data", RW: true},
		{Type: "bind", Source: filepath.Join(directory, "secrets/postgres"), Destination: "/run/secrets"},
		{Type: "bind", Source: filepath.Join(directory, "00-nethub-roles.sh"), Destination: "/docker-entrypoint-initdb.d/00-nethub-roles.sh"},
	}}
	encoded, _ := json.Marshal(value)
	if !guiDatabaseMounts(encoded, directory, project) {
		t.Fatal("expected existing deployment mount binding refused")
	}
	value.Mounts[1].RW = true
	encoded, _ = json.Marshal(value)
	if guiDatabaseMounts(encoded, directory, project) {
		t.Fatal("writable service secrets accepted")
	}
	value.Mounts[1].RW = false
	value.Mounts[0].Name = "foreign_database"
	encoded, _ = json.Marshal(value)
	if guiDatabaseMounts(encoded, directory, project) {
		t.Fatal("unrelated database volume accepted")
	}
	value.Mounts[0].Name = project + "_database"
	value.WorkingDir = filepath.Join(directory, "other")
	encoded, _ = json.Marshal(value)
	if guiDatabaseMounts(encoded, directory, project) {
		t.Fatal("unrelated Compose working directory accepted")
	}
}
