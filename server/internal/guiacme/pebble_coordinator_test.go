package guiacme_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/http01"
)

// This file-backed test store deliberately exercises worker/account recreation.
// It is not a SQL substitute: real-role PostgreSQL acceptance remains separate.
type fixtureCheckpoint struct {
	Version               int64
	Frame                 json.RawMessage
	LostProof, LostIssued bool
	Chain                 []byte
}
type fixtureJobs struct {
	path    string
	work    guiissuer.Snapshot
	account *guiacme.AccountStore
	t       *testing.T
}

func (s *fixtureJobs) load() fixtureCheckpoint {
	s.t.Helper()
	b, err := os.ReadFile(s.path)
	var v fixtureCheckpoint
	if err != nil || json.Unmarshal(b, &v) != nil {
		s.t.Fatal("fixture checkpoint unreadable")
	}
	return v
}
func (s *fixtureJobs) write(v fixtureCheckpoint) {
	s.t.Helper()
	b, err := json.Marshal(v)
	if err != nil || os.WriteFile(s.path, b, 0600) != nil {
		s.t.Fatal("fixture checkpoint write failed")
	}
}
func (s *fixtureJobs) match(w guiissuer.Snapshot) bool {
	return w.Lease.ID == s.work.Lease.ID && w.Lease.Token == s.work.Lease.Token && w.Lease.Version == s.load().Version
}
func (s *fixtureJobs) Renew(_ context.Context, w guiissuer.Snapshot) (guiissuer.Snapshot, error) {
	if !s.match(w) {
		return guiissuer.Snapshot{}, guiissuer.ErrDatabase
	}
	v := s.load()
	v.Version++
	s.write(v)
	w.Lease.Version = v.Version
	return w, nil
}
func (s *fixtureJobs) Read(_ context.Context, w guiissuer.Snapshot) (guiissuer.Progress, error) {
	if !s.match(w) {
		return guiissuer.Progress{}, guiissuer.ErrDatabase
	}
	v := s.load()
	if len(v.Frame) == 0 || bytes.Equal(v.Frame, []byte("null")) {
		return guiissuer.Progress{Phase: "new"}, nil
	}
	return guiissuer.DecodeProgress(v.Frame, w, s.account.AllowsURL)
}
func (s *fixtureJobs) Save(_ context.Context, w guiissuer.Snapshot, p guiissuer.Progress) (guiissuer.Snapshot, error) {
	if !s.match(w) {
		return guiissuer.Snapshot{}, guiissuer.ErrDatabase
	}
	b, err := guiissuer.EncodeProgress(p, w, s.account.AllowsURL)
	if err != nil {
		return guiissuer.Snapshot{}, err
	}
	v := s.load()
	v.Version++
	v.Frame, _ = json.Marshal(struct {
		Phase      string          `json:"phase"`
		Checkpoint json.RawMessage `json:"checkpoint"`
	}{p.Phase, b})
	lost := false
	if p.Phase == "proof_live" && !v.LostProof {
		v.LostProof = true
		lost = true
	}
	if p.Phase == "finalizing" && p.Order.Status == "valid" && !v.LostIssued {
		v.LostIssued = true
		lost = true
	}
	s.write(v)
	if lost {
		return guiissuer.Snapshot{}, guiissuer.ErrDatabase
	}
	w.Lease.Version = v.Version
	return w, nil
}
func (s *fixtureJobs) Release(_ context.Context, w guiissuer.Snapshot, reason string) error {
	if !s.match(w) || reason != "waiting" {
		return guiissuer.ErrDatabase
	}
	return nil
}
func (s *fixtureJobs) Finish(_ context.Context, w guiissuer.Snapshot, m guiissuer.Material) (string, error) {
	if !s.match(w) {
		return "", guiissuer.ErrDatabase
	}
	v := s.load()
	v.Chain = bytes.Clone(m.PEM)
	s.write(v)
	return "11111111-1111-1111-1111-111111111111", nil
}

func TestPebbleCoordinatorRecovery(t *testing.T) {
	guiacme.RunPebbleIssuerFixture(t, func(account *guiacme.AccountStore, publisher *http01.Publisher, roots *x509.CertPool, csr []byte, public string, reopen func() *guiacme.AccountStore) guiacme.Order {
		now := time.Now().UTC()
		request, err := guicert.ValidateBoundCSR(csr, "abcdefgh.devices.example.test", public)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := sha256.Sum256(request.DER)
		lease := guiissuer.Lease{ID: "11111111-1111-1111-1111-111111111111", TenantID: "22222222-2222-2222-2222-222222222222", DeviceID: "33333333-3333-3333-3333-333333333333", RequestID: "44444444-4444-4444-4444-444444444444", Token: "55555555-5555-5555-5555-555555555555", Version: 2, Generation: 1, Expires: now.Add(120 * time.Second), Deadline: now.Add(2 * time.Hour)}
		work := guiissuer.Snapshot{Lease: lease, Host: "abcdefgh.devices.example.test", PublicKey: public, CSRFingerprint: hex.EncodeToString(fingerprint[:]), CSR: bytes.Clone(csr)}
		path := filepath.Join(t.TempDir(), "checkpoint.json")
		store := &fixtureJobs{path: path, work: work, account: account, t: t}
		store.write(fixtureCheckpoint{Version: 2})
		coordinator := &guiissuer.Coordinator{Store: store, Account: account, Publisher: publisher, Roots: roots}
		interruptions := 0
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			before, readErr := store.Read(context.Background(), work)
			if readErr != nil {
				t.Fatal("fixture pre-step checkpoint rejected")
			}
			t.Logf("coordinator phase=%s version=%d interruptions=%d", before.Phase, work.Lease.Version, interruptions)
			result, err := coordinator.Step(context.Background(), work)
			if err != nil {
				interruptions++
				if interruptions > 2 {
					t.Fatal("unexpected coordinator failure", err)
				}
				// Recreate both the account handle and checkpoint reader after a
				// committed write loses its reply. No in-memory progress survives.
				account = reopen()
				store = &fixtureJobs{path: path, work: work, account: account, t: t}
				work.Lease.Version = store.load().Version
				coordinator = &guiissuer.Coordinator{Store: store, Account: account, Publisher: publisher, Roots: roots}
				continue
			}
			work = result.Work
			if result.State == "issued" {
				checkpoint := store.load()
				if interruptions != 2 || !checkpoint.LostProof || !checkpoint.LostIssued {
					t.Fatal("required interruptions did not execute")
				}
				if _, err := guicert.ValidateChain(checkpoint.Chain, csr, work.Host, roots, time.Now()); err != nil {
					t.Fatal("persisted original-key chain failed independent trust", err)
				}
				progress, err := store.Read(context.Background(), work)
				if err != nil || progress.Order == nil || progress.Order.Status != "valid" || !progress.Retired {
					t.Fatal("completed checkpoint mismatch")
				}
				t.Log("Coordinator recovered both published-proof and issued-order lost replies using persisted checkpoints and reopened account; independently trusted original-key chain retained")
				return *progress.Order
			}
			if result.State != "progressed" && result.State != "waiting" {
				t.Fatal("unexpected terminal coordinator outcome")
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("coordinator did not finish bounded genuine CA flow")
		return guiacme.Order{}
	})
}
