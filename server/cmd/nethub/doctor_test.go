package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoctorLoopbackHealthBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	var out, diagnostic bytes.Buffer
	if status := run([]string{"doctor", "--health-url", server.URL + "/healthz"}, &out, &diagnostic); status != 0 || out.Len() == 0 {
		t.Fatal("loopback health failed")
	}
	for _, target := range []string{"https://console.example.com/healthz", "http://192.0.2.1/healthz", server.URL + "/private", server.URL + "/healthz?token=secret", "http://user@127.0.0.1/healthz"} {
		out.Reset()
		diagnostic.Reset()
		if status := run([]string{"doctor", "--health-url", target}, &out, &diagnostic); status != 2 || out.Len() != 0 {
			t.Fatal("non-loopback or credential-bearing health target accepted")
		}
	}
}

func TestDoctorAuditModeBoundary(t *testing.T) {
	for _, args := range [][]string{
		{"--audit"},
		{"--password-file", "unused"},
		{"--audit-timezone", "UTC"},
		{"--audit", "--password-file", "unused", "--health-url", "http://127.0.0.1/healthz"},
		{"--audit", "--password-file", "unused", "--directory", "."},
		{"--audit", "--password-file", "unused", "--expected-address", "192.0.2.1"},
		{"--audit", "--password-file", "unused", "--public-tls"},
		{"--audit", "--password-file", "unused", "--port", "65536"},
		{"--audit", "--password-file", "unused", "--sslmode", "prefer"},
		{"--audit", "--password-file", "unused", "--audit-timeout", "0s"},
		{"--audit", "--password-file", "unused", "--audit-timeout", "6m"},
	} {
		var out, diagnostic bytes.Buffer
		if status := run(append([]string{"doctor"}, args...), &out, &diagnostic); status != 2 || out.Len() != 0 {
			t.Fatal("ambiguous audit/database mode reached execution", args, status)
		}
	}
}

func TestDoctorPublicTLSRefusesPrivateHealthMode(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if status := run([]string{"doctor", "--public-tls", "--health-url", "http://127.0.0.1/healthz"}, &out, &diagnostic); status != 2 || out.Len() != 0 {
		t.Fatal("public TLS and private health modes were combined")
	}
}

func TestDoctorRuntimeRolesModeBoundary(t *testing.T) {
	for _, args := range [][]string{
		{"--database-roles"},
		{"--database-roles", "--audit", "--password-file", "unused"},
		{"--database-roles", "--password-file", "unused", "--public-tls"},
		{"--database-roles", "--password-file", "unused", "--directory", "."},
		{"--database-roles", "--password-file", "unused", "--audit-timezone", "UTC"},
		{"--database-roles", "--password-file", "unused", "--audit-timeout", "30s"},
		{"--database-roles", "--password-file", "unused", "--sslmode", "prefer"},
		{"--database-roles", "--password-file", "unused", "--port", "65536"},
	} {
		var out, diagnostic bytes.Buffer
		if status := run(append([]string{"doctor"}, args...), &out, &diagnostic); status != 2 || out.Len() != 0 {
			t.Fatal("ambiguous runtime-role mode reached database execution", args, status)
		}
	}
}

func TestDoctorRuntimeContainerModeBoundary(t *testing.T) {
	for _, args := range [][]string{
		{"--project", "other"}, {"--compose-file", "unused"},
		{"--runtime-containers", "--database-roles"},
		{"--runtime-containers", "--public-tls"},
		{"--runtime-containers", "--expected-address", "192.0.2.1"},
		{"--runtime-containers", "--password-file", "unused"},
		{"--runtime-containers", "--health-url", "http://127.0.0.1/healthz"},
	} {
		var out, diagnostic bytes.Buffer
		if status := run(append([]string{"doctor"}, args...), &out, &diagnostic); status != 2 || out.Len() != 0 {
			t.Fatal("ambiguous container mode reached Docker execution", args, status)
		}
	}
}
