package relayprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/fatedier/yamux"
)

func TestRejectionRequiresExactBoundedProtocolResult(t *testing.T) {
	for _, raw := range []string{
		`{"version":"0.71.1","error":"not_authorized"}`,
		`{"version":"0.71.1","error":"not_authorized","run_id":""}`,
	} {
		if version, err := rejectionVersion([]byte(raw)); err != nil || version != ProtocolVersion {
			t.Fatal("expected denial refused")
		}
	}
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"version":"0.71.1","error":""}`,
		`{"version":"0.71.1","error":"not_authorized","run_id":"accepted"}`,
		`{"version":"0.71.1","error":"unavailable"}`,
		`{"version":"0.71.1","error":"send Login request to plugin error"}`,
		`{"version":"0.71.1","error":"token in login doesn't match token from configuration"}`,
		`{"version":"0.71.1","error":"not_authorized","run_id":null}`,
		`{"version":"0.71.1","error":"not_authorized","other":"private"}`,
		`{"version":"0.71.1","version":"0.71.1","error":"not_authorized"}`,
		`{"version":"0.71.1","error":"not_authorized"}{}`,
		`{"version":"0.71.1+unknown","error":"not_authorized"}`,
		`{"version":"00.71.1","error":"not_authorized"}`,
	} {
		if _, err := rejectionVersion([]byte(raw)); err == nil {
			t.Fatal("unexpected relay response accepted", raw)
		}
	}
}

func probeFixture(t *testing.T, kind byte, length uint64, response string, stall bool) (string, []byte, <-chan bool) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	certificate := seed.TLS.Certificates[0]
	seed.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan bool, 1)
	go func() {
		valid := false
		defer func() { done <- valid }()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		config := yamux.DefaultConfig()
		config.EnableKeepAlive = false
		config.LogOutput = io.Discard
		session, err := yamux.Server(connection, config)
		if err != nil {
			return
		}
		defer session.Close()
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		header := make([]byte, 9)
		if _, err = io.ReadFull(stream, header); err != nil || header[0] != 'o' {
			return
		}
		size := binary.BigEndian.Uint64(header[1:])
		if size == 0 || size > 1024 {
			return
		}
		body := make([]byte, int(size))
		if _, err = io.ReadFull(stream, body); err != nil {
			return
		}
		var request map[string]json.RawMessage
		if json.Unmarshal(body, &request) != nil || len(request) != 2 {
			return
		}
		var version string
		var metas map[string]string
		if json.Unmarshal(request["version"], &version) != nil || version != ProtocolVersion || json.Unmarshal(request["metas"], &metas) != nil || len(metas) != 2 || metas["domain_claim"] != "doctor-invalid-claim" || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(metas["device_id"]) {
			return
		}
		valid = true
		if stall {
			var one [1]byte
			stream.Read(one[:])
			return
		}
		header[0] = kind
		binary.BigEndian.PutUint64(header[1:], length)
		if _, err = stream.Write(header); err != nil {
			return
		}
		if length <= 4096 {
			stream.Write([]byte(response))
		}
		var one [1]byte
		if n, _ := stream.Read(one[:]); n != 0 {
			valid = false
		}
	}()
	return listener.Addr().String(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), done
}

func TestProbeUsesVerifiedTLSMuxAndOnlyOneUncredentialedDeniedLogin(t *testing.T) {
	response := `{"version":"0.71.1","error":"not_authorized"}`
	for _, test := range []struct {
		name   string
		kind   byte
		length uint64
		body   string
		valid  bool
	}{
		{"denied", '1', uint64(len(response)), response, true},
		{"wrong_message", '2', uint64(len(response)), response, false},
		{"oversized", '1', 4097, "", false},
		{"unavailable", '1', uint64(len(`{"version":"0.71.1","error":"unavailable"}`)), `{"version":"0.71.1","error":"unavailable"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, ca, done := probeFixture(t, test.kind, test.length, test.body, false)
			version, err := Check(context.Background(), address, "127.0.0.1", ca)
			if (err == nil) != test.valid || test.valid && version != ProtocolVersion {
				t.Fatal("unexpected probe result")
			}
			select {
			case valid := <-done:
				if !valid {
					t.Fatal("probe sent unexpected identity or extra messages")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("fixture did not stop")
			}
		})
	}
}

func TestProbeRefusesUntrustedTLSAndHonorsCancellation(t *testing.T) {
	address, ca, done := probeFixture(t, '1', 0, "", false)
	if _, err := Check(context.Background(), address, "wrong.invalid", ca); err == nil {
		t.Fatal("wrong TLS hostname accepted")
	}
	select {
	case sentLogin := <-done:
		if sentLogin {
			t.Fatal("wrong-hostname TLS sent a Login")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("TLS fixture did not stop")
	}
	unrelated, err := relaycert.Create("other.example.com", time.Now())
	if err != nil {
		t.Fatal("unrelated test CA creation failed")
	}
	address, _, done = probeFixture(t, '1', 0, "", false)
	if _, err := Check(context.Background(), address, "127.0.0.1", unrelated.CA); err == nil {
		t.Fatal("untrusted relay CA accepted")
	}
	select {
	case sentLogin := <-done:
		if sentLogin {
			t.Fatal("untrusted TLS sent a Login")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("untrusted TLS fixture did not stop")
	}
	address, ca, done = probeFixture(t, '1', 0, "", true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := Check(ctx, address, "127.0.0.1", ca); err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("stalled probe ignored deadline")
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("cancelled probe left fixture running")
	}
	for _, address := range []string{"192.0.2.1:7000", "console.example.com:7000", "127.0.0.1:0"} {
		if _, err := Check(context.Background(), address, "console.example.com", ca); err == nil {
			t.Fatal("nonlocal or invalid relay endpoint accepted")
		}
	}
}
