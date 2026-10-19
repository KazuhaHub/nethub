package relaymaint

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func expireFixture(t *testing.T, e Engine, f *serviceFixture) {
	t.Helper()
	block, _ := pem.Decode(f.cert)
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
	leaf.NotAfter = e.now().Add(-time.Second)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	f.cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.original, err = materialID(f.cert, f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.loaded = f.original
}

func TestExpiredLeafRecoveryAndRollbackRefusal(t *testing.T) {
	for _, fail := range []bool{false, true} {
		e, f, _ := fixture(t)
		expireFixture(t, e, f)
		if fail {
			f.failNew = 1
		}
		state, err := e.Run(context.Background(), false)
		if fail {
			if err != ErrMaintenance || state.Phase != "recovery-failed" || state.LastGood != "" || f.publishes != 1 || f.restarts != 1 {
				t.Fatal("expired original was treated as valid rollback")
			}
		} else if err != nil || state.LastGood == f.original || state.Assessment.Expired {
			t.Fatal("expired leaf was not replaced")
		}
	}
}

func TestAuthorityExpiryAndStoppedExplicitRetry(t *testing.T) {
	e, f, now := fixture(t)
	caBlock, _ := pem.Decode(e.CA)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	*now = ca.NotAfter.Add(time.Second)
	state, err := e.Run(context.Background(), false)
	if err != ErrMaintenance || state.ErrorCode != "authority_expired" || !state.Assessment.AuthorityExpired || f.restarts != 0 {
		t.Fatal("expired authority triggered issuance")
	}
	e, f, _ = fixture(t)
	f.failNew = 1
	state, err = e.Run(context.Background(), false)
	if err != ErrMaintenance {
		t.Fatal("fixture apply did not fail")
	}
	candidate := state.Candidate
	f.running = false
	if _, err = e.Run(context.Background(), false); err != ErrMaintenance {
		t.Fatal("stopped service not reported")
	}
	before := f.restarts
	state, err = e.Run(context.Background(), true)
	if err != nil || state.LastGood != candidate || f.restarts != before+1 {
		t.Fatal("explicit host recovery could not restart pending generation")
	}
}

func TestLinkedStateAndCorruptGenerationRefused(t *testing.T) {
	e, f, _ := fixture(t)
	id, _, _ := prepareInterrupted(t, e, f, "issued")
	key := filepath.Join(e.Directory, "secrets/issuer/maintenance", id, "key.pem")
	if os.WriteFile(key, []byte("corrupt"), 0600) != nil {
		t.Fatal("fixture corruption")
	}
	if _, err := e.Run(context.Background(), false); err != ErrState || f.restarts != 0 || f.publishes != 0 {
		t.Fatal("corrupt pending key caused application")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged Windows symlink creation is not part of Linux host acceptance")
	}
	e, f, _ = fixture(t)
	issuer := filepath.Join(e.Directory, "secrets/issuer")
	if os.Symlink(t.TempDir(), filepath.Join(issuer, "maintenance")) != nil {
		t.Fatal("fixture symlink")
	}
	if _, err := e.Run(context.Background(), false); err != ErrState || f.restarts != 0 {
		t.Fatal("linked journal directory accepted")
	}
}
