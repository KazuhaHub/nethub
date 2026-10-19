package relaymaint

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

type serviceFixture struct {
	cert, key           []byte
	loaded, original    string
	running             bool
	failNew             int
	failAll             bool
	restarts, publishes int
}

type invalidBinding struct{ Service }

func (invalidBinding) Running(context.Context) (bool, error) { return false, ErrState }

func (f *serviceFixture) Running(context.Context) (bool, error) { return f.running, nil }
func (f *serviceFixture) Current() ([]byte, []byte, error) {
	return bytes.Clone(f.cert), bytes.Clone(f.key), nil
}
func (f *serviceFixture) Publish(cert, key []byte) error {
	f.publishes++
	f.cert, f.key = bytes.Clone(cert), bytes.Clone(key)
	return nil
}
func (f *serviceFixture) Restart(context.Context) error {
	f.restarts++
	id, err := materialID(f.cert, f.key)
	if err != nil {
		return err
	}
	if f.failAll || id != f.original && f.failNew > 0 {
		if f.failNew > 0 {
			f.failNew--
		}
		return errors.New("fixture restart failure")
	}
	f.loaded = id
	f.running = true
	return nil
}
func (f *serviceFixture) Observe(context.Context) (string, error) { return f.loaded, nil }

func fixture(t *testing.T) (Engine, *serviceFixture, *time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	m, err := relaycert.Create("relay.example.test", now.Add(-3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(m.CA)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(m.CAKey)
	signer, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leafBlock, _ := pem.Decode(m.Certificate)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotBefore = now.Add(-2 * time.Hour)
	leaf.NotAfter = now.Add(15 * time.Minute)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, signer.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	m.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	id, err := materialID(m.Certificate, m.Key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if os.MkdirAll(filepath.Join(directory, "secrets/issuer"), 0700) != nil {
		t.Fatal("fixture directory")
	}
	f := &serviceFixture{cert: m.Certificate, key: m.Key, loaded: id, original: id, running: true}
	e := Engine{Directory: directory, Name: "relay.example.test", CA: m.CA, CAKey: m.CAKey, Service: f, Now: func() time.Time { return now }}
	return e, f, &now
}

func TestDurableRenewalAndUnchangedSuppression(t *testing.T) {
	e, f, _ := fixture(t)
	state, err := e.Run(context.Background(), false)
	if err != nil || state.Phase != "idle" || state.LastGood == f.original || state.Candidate != "" || f.restarts != 1 || state.AppliedAt.IsZero() {
		t.Fatalf("renewal failed: %+v %v", state, err)
	}
	if state.Assessment == nil || state.Assessment.Due {
		t.Fatal("fresh renewal remains due")
	}
	for range 3 {
		if _, err := e.Run(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if f.restarts != 1 || f.publishes != 1 {
		t.Fatal("unchanged generation restarted")
	}
	encoded, _ := json.Marshal(state)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, e.CAKey) {
		t.Fatal("private material in status")
	}
	if !missing(filepath.Join(e.Directory, "secrets/issuer/maintenance/pending")) {
		t.Fatal("completed candidate not retired")
	}
}

func TestRetryBudgetReusesIssuedGeneration(t *testing.T) {
	e, f, now := fixture(t)
	f.failNew = 3
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Phase != "waiting" || state.Attempts != 1 || f.loaded != f.original {
		t.Fatal("first failed apply was not rolled back")
	}
	candidate := state.Candidate
	_, err = e.Run(context.Background(), false)
	if err != nil || f.restarts != 2 {
		t.Fatal("backoff was ignored")
	}
	for attempt := 2; attempt <= 3; attempt++ {
		*now = state.NextAttempt.Add(time.Second)
		state, err = e.Run(context.Background(), false)
		if err != ErrMaintenance || state.Candidate != candidate || state.Attempts != attempt || f.loaded != f.original {
			t.Fatal("retry reissued or lost rollback")
		}
	}
	if state.Phase != "exhausted" || f.restarts != 6 {
		t.Fatal("attempt budget not enforced")
	}
	for range 3 {
		_, _ = e.Run(context.Background(), false)
	}
	if f.restarts != 6 {
		t.Fatal("exhausted job restarted")
	}
	e.Service = invalidBinding{f}
	state, err = e.Run(context.Background(), true)
	if err != ErrMaintenance || state.Attempts != 3 || state.Phase != "exhausted" || f.restarts != 6 {
		t.Fatal("invalid project binding reset the retry budget")
	}
	e.Service = f
	state, err = e.Run(context.Background(), true)
	if err != nil || state.LastGood != candidate || f.restarts != 7 {
		t.Fatal("operator retry did not reuse issued generation")
	}
}

func TestStoppedServiceAndRollbackFailure(t *testing.T) {
	e, f, _ := fixture(t)
	f.running = false
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.ErrorCode != "service_stopped" || f.restarts != 0 || f.publishes != 0 {
		t.Fatal("timer started a stopped service")
	}
	f.running = true
	f.failAll = true
	state, err = e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Phase != "recovery-failed" || state.ErrorCode != "rollback_failed" {
		t.Fatal("rollback failure hidden")
	}
	restarts := f.restarts
	_, _ = e.Run(context.Background(), false)
	if f.restarts != restarts {
		t.Fatal("terminal rollback failure retried silently")
	}
	f.failAll = false
	state, err = e.Run(context.Background(), true)
	if err != nil || state.Phase != "idle" {
		t.Fatal("explicit recovery retry failed")
	}
}

func prepareInterrupted(t *testing.T, e Engine, f *serviceFixture, phase string) (string, []byte, []byte) {
	t.Helper()
	s, err := openStore(filepath.Join(e.Directory, "secrets/issuer/maintenance"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	old, err := s.put(f.cert, f.key)
	if err != nil {
		t.Fatal(err)
	}
	next, err := relaycert.Renew(e.CA, e.CAKey, e.Name, e.now())
	if err != nil {
		t.Fatal(err)
	}
	if s.putPair("pending", next.Certificate, next.Key) != nil {
		t.Fatal("pending fixture")
	}
	id, err := s.put(next.Certificate, next.Key)
	if err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Phase: phase, LastGood: old, Original: old}
	if phase != "idle" {
		state.Candidate = id
		state.Attempts = 1
	}
	if s.save(state) != nil {
		t.Fatal("journal fixture")
	}
	return id, next.Certificate, next.Key
}

func TestRestartRecoveryAtDurableBoundaries(t *testing.T) {
	for _, phase := range []string{"idle", "issued", "applying", "rollback"} {
		t.Run(phase, func(t *testing.T) {
			e, f, _ := fixture(t)
			id, cert, _ := prepareInterrupted(t, e, f, phase)
			if phase == "applying" {
				f.cert = cert
			} // Mixed runtime files after a process interruption.
			state, err := e.Run(context.Background(), false)
			if phase == "rollback" {
				if err != ErrMaintenance || state.Phase != "waiting" || f.loaded != f.original {
					t.Fatal("interrupted rollback did not recover")
				}
			} else if err != nil || state.LastGood != id || f.loaded != id || f.restarts != 1 {
				t.Fatalf("candidate was not reused: %+v %v", state, err)
			}
		})
	}
	t.Run("already served", func(t *testing.T) {
		e, f, _ := fixture(t)
		id, cert, key := prepareInterrupted(t, e, f, "applying")
		f.cert, f.key, f.loaded = cert, key, id
		state, err := e.Run(context.Background(), false)
		if err != nil || state.LastGood != id || f.restarts != 0 || f.publishes != 0 {
			t.Fatal("verified applied generation restarted after crash")
		}
	})
	t.Run("success before pending retirement", func(t *testing.T) {
		e, f, _ := fixture(t)
		id, cert, key := prepareInterrupted(t, e, f, "idle")
		f.cert, f.key, f.loaded = cert, key, id
		if _, err := e.Run(context.Background(), false); err != nil || f.restarts != 0 || !missing(filepath.Join(e.Directory, "secrets/issuer/maintenance/pending")) {
			t.Fatal("pending cleanup recovery failed")
		}
	})
}

func TestJournalLeaseAndCorruption(t *testing.T) {
	e, f, _ := fixture(t)
	root := filepath.Join(e.Directory, "secrets/issuer/maintenance")
	s, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), false); err != ErrBusy {
		t.Fatal("second operation acquired lease")
	}
	s.close()
	if err := replacePrivate(filepath.Join(root, "state.json"), []byte(`{"version":1,"phase":"idle","unexpected":"value"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), false); err != ErrState || f.restarts != 0 {
		t.Fatal("corrupt journal caused mutation")
	}
}
