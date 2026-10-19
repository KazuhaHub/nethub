package relaymaint

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

func shortCandidate(t *testing.T, e Engine, wrongName bool) ([]byte, []byte) {
	t.Helper()
	material, err := relaycert.Renew(e.CA, e.CAKey, e.Name, e.now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material.Certificate)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(e.CA)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(e.CAKey)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = e.now().Add(time.Minute)
	if wrongName {
		leaf.DNSNames = []string{"another.example.test"}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), material.Key
}

func expiredJob(t *testing.T, phase string, wrongName bool) (Engine, *serviceFixture, *time.Time, string) {
	t.Helper()
	e, f, now := fixture(t)
	s, err := openStore(filepath.Join(e.Directory, "secrets/issuer/maintenance"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	old, err := s.put(f.cert, f.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := shortCandidate(t, e, wrongName)
	id, err := s.put(cert, key)
	if err != nil || s.putPair("pending", cert, key) != nil {
		t.Fatal("candidate fixture")
	}
	state := State{Version: 1, Phase: phase, Original: old, LastGood: old, Candidate: id, Attempts: 1}
	switch phase {
	case "idle":
		state.Candidate = ""
		state.Attempts = 0
	case "waiting":
		state.NextAttempt = e.now().Add(time.Minute)
	case "exhausted":
		state.Attempts = 3
	case "replacing":
		state.Superseded = id
		state.Attempts = 0
	}
	if s.save(state) != nil {
		t.Fatal("candidate journal fixture")
	}
	*now = now.Add(time.Minute)
	return e, f, now, id
}

func TestExpiredCandidateReplacedWithoutDiscardingHistory(t *testing.T) {
	for _, phase := range []string{"idle", "issued", "waiting", "applying", "replacing"} {
		t.Run(phase, func(t *testing.T) {
			e, f, _, expired := expiredJob(t, phase, false)
			state, err := e.Run(context.Background(), false)
			if err != nil || state.Phase != "idle" || state.LastGood == expired || state.LastGood == f.original || state.Superseded != expired || f.restarts != 1 {
				t.Fatalf("expired replacement failed: %+v %v", state, err)
			}
			s, err := openStore(filepath.Join(e.Directory, "secrets/issuer/maintenance"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			cert, key, err := s.generation(expired)
			if err != nil {
				t.Fatal("superseded immutable generation lost")
			}
			assessment, err := relaycert.Assess(e.CA, cert, key, e.Name, e.now())
			if err != nil || !assessment.Expired {
				t.Fatal("wrong generation superseded")
			}
			if _, _, err = s.generation(state.LastGood); err != nil || !missing(filepath.Join(s.root, "pending")) {
				t.Fatal("replacement not durable or pending not retired")
			}
		})
	}
}

func TestExpiredCandidateDoesNotBypassExhaustionOrStoppedIntent(t *testing.T) {
	e, f, _, expired := expiredJob(t, "exhausted", false)
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Candidate != expired || f.publishes != 0 {
		t.Fatal("exhausted job silently replaced")
	}
	state, err = e.Run(context.Background(), true)
	if err != nil || state.LastGood == expired || state.Superseded != expired {
		t.Fatal("explicit expired retry did not replace")
	}
	e, f, _, expired = expiredJob(t, "issued", false)
	f.running = false
	state, err = e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Candidate != expired || state.ErrorCode != "service_stopped" || f.publishes != 0 {
		t.Fatal("stopped service restarted implicitly")
	}
	state, err = e.Run(context.Background(), true)
	if err != nil || state.LastGood == expired || !f.running {
		t.Fatal("explicit stopped recovery failed")
	}
}

func TestInterruptedReplacementReusesDurablePending(t *testing.T) {
	for _, boundary := range []string{"retired", "pending", "issued"} {
		t.Run(boundary, func(t *testing.T) {
			e, f, _, expired := expiredJob(t, "replacing", false)
			s, err := openStore(filepath.Join(e.Directory, "secrets/issuer/maintenance"))
			if err != nil {
				t.Fatal(err)
			}
			if removePending(s) != nil {
				t.Fatal("retirement fixture")
			}
			expected := ""
			if boundary != "retired" {
				material, err := relaycert.Renew(e.CA, e.CAKey, e.Name, e.now())
				if err != nil || s.putPair("pending", material.Certificate, material.Key) != nil {
					t.Fatal("fresh pending fixture")
				}
				expected, err = materialID(material.Certificate, material.Key)
				if err != nil {
					t.Fatal(err)
				}
				if boundary == "issued" {
					if _, err = s.put(material.Certificate, material.Key); err != nil {
						t.Fatal(err)
					}
					state, err := s.load()
					if err != nil {
						t.Fatal(err)
					}
					state.Candidate = expected
					state.Phase = "issued"
					if s.save(state) != nil {
						t.Fatal("issued replacement journal")
					}
				}
			}
			s.close()
			state, err := e.Run(context.Background(), false)
			if err != nil || state.Superseded != expired || state.LastGood == expired || f.restarts != 1 || expected != "" && state.LastGood != expected {
				t.Fatalf("replacement boundary recovery failed: %+v %v", state, err)
			}
		})
	}
}

func TestValidReplacementRetryIsNotReissued(t *testing.T) {
	e, f, now, expired := expiredJob(t, "issued", false)
	f.failNew = 1
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Phase != "waiting" || state.Candidate == expired || state.Superseded != expired || f.loaded != f.original {
		t.Fatal("replacement failure did not roll back")
	}
	candidate := state.Candidate
	*now = now.Add(2 * time.Minute)
	state, err = e.Run(context.Background(), false)
	if err != nil || state.LastGood != candidate || state.Superseded != expired {
		t.Fatal("valid replacement reissued instead of retried")
	}
}

func TestExpiredWrongIdentityIsNotReplaced(t *testing.T) {
	e, f, _, expired := expiredJob(t, "issued", true)
	root := filepath.Join(e.Directory, "secrets/issuer/maintenance")
	s, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	beforeCert, beforeKey, err := s.pair("pending")
	s.close()
	if err != nil {
		t.Fatal(err)
	}
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.ErrorCode != "candidate_invalid" || state.Candidate != expired || state.Superseded != "" || f.publishes != 0 {
		t.Fatal("wrong identity was replaced or applied")
	}
	s, err = openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	afterCert, afterKey, err := s.pair("pending")
	if err != nil || !bytes.Equal(beforeCert, afterCert) || !bytes.Equal(beforeKey, afterKey) {
		t.Fatal("invalid pending material silently discarded")
	}
}

func TestExpiredFinalAttemptRequiresRollbackAndExplicitReplacement(t *testing.T) {
	e, f, _, expired := expiredJob(t, "applying", false)
	s, err := openStore(filepath.Join(e.Directory, "secrets/issuer/maintenance"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	state.Attempts = 3
	if s.save(state) != nil {
		t.Fatal("last attempt fixture")
	}
	s.close()
	state, err = e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Phase != "exhausted" || state.Candidate != expired || state.Superseded != "" || f.loaded != f.original || f.restarts != 1 {
		t.Fatal("expired interrupted final attempt spent another deployment")
	}
	state, err = e.Run(context.Background(), true)
	if err != nil || state.LastGood == expired || state.Superseded != expired {
		t.Fatal("explicit replacement after final rollback failed")
	}
}

func TestExpiredReplacementNeverRestoresExpiredLastGood(t *testing.T) {
	e, f, now, expired := expiredJob(t, "issued", false)
	*now = now.Add(20 * time.Minute)
	f.failNew = 1
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.Phase != "recovery-failed" || state.Candidate == expired || f.publishes != 1 || f.restarts != 1 {
		t.Fatal("expired last-good was published as rollback")
	}
	candidate := state.Candidate
	state, err = e.Run(context.Background(), true)
	if err != nil || state.LastGood != candidate || state.Superseded != expired {
		t.Fatal("explicit recovery reissued the valid replacement")
	}
}

func TestCancelledExpiredReplacementPreservesPending(t *testing.T) {
	e, f, _, expired := expiredJob(t, "issued", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state, err := e.Run(ctx, false)
	if err != ErrMaintenance || state.ErrorCode != "interrupted" || state.Candidate != expired || state.Superseded != "" || f.publishes != 0 {
		t.Fatal("cancelled operation replaced the candidate")
	}
}
