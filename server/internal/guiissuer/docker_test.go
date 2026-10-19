package guiissuer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func dockerFixture() (DockerBinding, map[string]any) {
	b := DockerBinding{ContainerID: strings.Repeat("a", 64), ImageID: "sha256:" + strings.Repeat("b", 64), Project: "nethub-fixture"}
	return b, map[string]any{"id": b.ContainerID, "image": b.ImageID, "project": b.Project, "service": "postgres", "running": true, "privileged": false, "network": "nethub-fixture_database", "ports": map[string]any{}}
}

func TestDockerSQLBindingRejectsReplacementAndExposure(t *testing.T) {
	b, good := dockerFixture()
	encoded, _ := json.Marshal(good)
	if !b.accepts(encoded) {
		t.Fatal("valid immutable binding rejected")
	}
	for field, replacement := range map[string]any{"id": strings.Repeat("c", 64), "image": "sha256:" + strings.Repeat("c", 64), "project": "other", "service": "web", "running": false, "privileged": true, "network": "host", "ports": map[string]any{"5432/tcp": []string{"published"}}} {
		_, value := dockerFixture()
		value[field] = replacement
		encoded, _ := json.Marshal(value)
		if b.accepts(encoded) {
			t.Fatalf("unsafe %s accepted", field)
		}
	}
	for field := range good {
		_, value := dockerFixture()
		delete(value, field)
		encoded, _ := json.Marshal(value)
		if b.accepts(encoded) {
			t.Fatalf("missing %s accepted", field)
		}
	}
	for _, network := range []string{"bridge", "container:other", "unrelated_database"} {
		_, value := dockerFixture()
		value["network"] = network
		encoded, _ := json.Marshal(value)
		if b.accepts(encoded) {
			t.Fatal("unbound network accepted")
		}
	}
	_, nullable := dockerFixture()
	nullable["privileged"] = nil
	encoded, _ = json.Marshal(nullable)
	if b.accepts(encoded) {
		t.Fatal("unknown privilege state accepted")
	}
	for _, value := range [][]byte{nil, append(encoded, encoded...), bytes.Repeat([]byte("x"), 4097)} {
		if b.accepts(value) {
			t.Fatal("ambiguous inspection accepted")
		}
	}
}

func TestPrivateDockerCommandHasFixedDaemonAndCleanEnvironment(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://untrusted.example.test:2375")
	t.Setenv("PGPASSWORD", "fixture-must-not-inherit")
	command := privateDockerCommand(context.Background(), "inspect", "fixture")
	if command.Path != "/usr/bin/docker" || !reflect.DeepEqual(command.Args[1:], []string{"--host", "unix:///var/run/docker.sock", "inspect", "fixture"}) {
		t.Fatal("alternate executable or daemon selected")
	}
	for _, value := range command.Env {
		if strings.Contains(value, "DOCKER") || strings.Contains(value, "PGPASSWORD") || strings.Contains(value, "fixture-must-not-inherit") {
			t.Fatal("private environment inherited")
		}
	}
	output := privateOutput{limit: 4}
	if _, err := output.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("secret")); err != ErrDatabase || !output.overflow || output.data.String() != "1234" {
		t.Fatal("overflow retained private trailing output")
	}
}

func TestNativeDockerSQLRunner(t *testing.T) {
	id := os.Getenv("NETHUB_TEST_GUI_SQL_CONTAINER")
	if id == "" {
		t.Skip("requires isolated host Docker/PostgreSQL acceptance")
	}
	b := DockerBinding{ContainerID: id, ImageID: os.Getenv("NETHUB_TEST_GUI_SQL_IMAGE"), Project: os.Getenv("NETHUB_TEST_GUI_SQL_PROJECT")}
	run, err := NewDockerSQLRunner(b)
	if err != nil {
		t.Fatal("host runner not ready")
	}
	body, err := run(context.Background(), []byte("SET SESSION AUTHORIZATION nethub_issuer;SELECT current_user,session_user;\n"))
	if err != nil || string(bytes.TrimSpace(body)) != "nethub_issuer|nethub_issuer" {
		t.Fatal("host runner did not select private socket/issuer identity")
	}
	body, err = run(context.Background(), []byte("SET SESSION AUTHORIZATION nethub_issuer;SELECT * FROM public.devices;\n"))
	if err != ErrDatabase || len(body) != 0 {
		t.Fatal("raw table permission or diagnostic escaped runner")
	}
	b.Project = "unrelated-fixture"
	wrong, err := NewDockerSQLRunner(b)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := wrong(context.Background(), []byte("SELECT 1;\n")); err != ErrDatabase || len(body) != 0 {
		t.Fatal("changed project binding accepted")
	}
	t.Log("Real host Docker runner verified exact immutable database identity, private socket, issuer SQL identity, raw-table denial and project-drift refusal")
}
