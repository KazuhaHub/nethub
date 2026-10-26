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
