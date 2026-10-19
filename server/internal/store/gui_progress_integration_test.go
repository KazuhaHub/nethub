package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
)

func testGUIProgress(t *testing.T, f *enrollmentFixture, work *guiissuer.Snapshot) *guiissuer.Snapshot {
	t.Helper()
	account, err := guiacme.NewAccountStore(filepath.Join(t.TempDir(), "account"), guiacme.Config{DirectoryURL: "https://acme.example.test/directory", ContactEmail: "issuer@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	read := func(w *guiissuer.Snapshot) guiissuer.Progress {
		t.Helper()
		l := w.Lease
		data, err := issuerSQL(f.ctx, fmt.Sprintf(`SELECT coalesce(public.read_gui_certificate_progress('%s','%s',%d),'null'::jsonb)`, l.ID, l.Token, l.Version))
		if err != nil {
			t.Fatal("private progress read failed")
		}
		p, err := guiissuer.DecodeProgress(bytes.TrimSpace(data), *w, account.AllowsURL)
		if err != nil {
			t.Fatal("persisted progress could not recover", err)
		}
		return p
	}
	save := func(w *guiissuer.Snapshot, p guiissuer.Progress, wantError bool) *guiissuer.Snapshot {
		t.Helper()
		checkpoint, err := guiissuer.EncodeProgress(p, *w, account.AllowsURL)
		if err != nil {
			t.Fatal(err)
		}
		l := w.Lease
		statement := fmt.Sprintf(`SELECT coalesce(public.save_gui_certificate_progress('%s','%s',%d,'%s','%s'::jsonb),'null'::jsonb)`, l.ID, l.Token, l.Version, p.Phase, strings.ReplaceAll(string(checkpoint), "'", "''"))
		data, err := issuerSQL(f.ctx, statement)
		if wantError {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 3 || !bytes.Contains(data, []byte("23514")) {
				t.Fatal("unsafe checkpoint update did not fail")
			}
			return nil
		}
		if err != nil {
			t.Fatal("private progress save failed")
		}
		if string(bytes.TrimSpace(data)) == "null" {
			return nil
		}
		next, err := guiissuer.DecodeSnapshot(bytes.TrimSpace(data), "devices.example.com", nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return &next
	}
	if read(work).Phase != "new" {
		t.Fatal("new job already has a remote order")
	}
	order := guiacme.Order{URI: "https://acme.example.test/order/original", Host: work.Host, RequestFingerprint: work.CSRFingerprint, Status: "ready", AuthorizationURL: "https://acme.example.test/authz/original", FinalizeURL: "https://acme.example.test/finalize/original", Expires: time.Now().UTC().Add(time.Hour)}
	save(work, guiissuer.Progress{Phase: "finalizing", Order: &order}, true)
	prior := *work
	work = save(work, guiissuer.Progress{Phase: "order_intent"}, false)
	if work == nil {
		t.Fatal("order creation intent was not durable")
	}
	if save(&prior, guiissuer.Progress{Phase: "order_intent"}, false) != nil {
		t.Fatal("stale lease version overwrote intent")
	}
	if read(work).Phase != "order_intent" {
		t.Fatal("lost creation reply would initialize blindly")
	}
	order.Status = "pending"
	work = save(work, guiissuer.Progress{Phase: "order_saved", Order: &order}, false)
	if work == nil {
		t.Fatal("known order identity was not saved")
	}
	for _, change := range []func(*guiacme.Order){
		func(o *guiacme.Order) { o.URI = "https://acme.example.test/order/replacement" },
		func(o *guiacme.Order) { o.Profile = "changed" },
		func(o *guiacme.Order) { o.AuthorizationURL = "https://acme.example.test/authz/replacement" },
		func(o *guiacme.Order) { o.FinalizeURL = "https://acme.example.test/finalize/replacement" },
	} {
		changed := order
		change(&changed)
		save(work, guiissuer.Progress{Phase: "order_saved", Order: &changed}, true)
	}
	proof := guiacme.HTTP01{Order: order, URI: "https://acme.example.test/challenge/original", Token: strings.Repeat("A", 22),
		KeyAuthorization: strings.Repeat("A", 22) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{21}, 32)), Status: "pending", ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	progress := guiissuer.Progress{Phase: "proof_saved", Order: &order, Proof: &proof, Generation: strings.Repeat("a", 32)}
	work = save(work, progress, false)
	if work == nil {
		t.Fatal("publication intent was not durable")
	}
	progress.Phase = "proof_live"
	work = save(work, progress, false)
	if work == nil {
		t.Fatal("published proof was not retained")
	}
	changedGeneration := progress
	changedGeneration.Generation = strings.Repeat("b", 32)
	save(work, changedGeneration, true)
	changedProof := proof
	changedProof.KeyAuthorization = proof.Token + "." + strings.Repeat("A", 43)
	changedPublication := progress
	changedPublication.Proof = &changedProof
	save(work, changedPublication, true)
	progress.Phase = "validating"
	proof.Status = "processing"
	work = save(work, progress, false)
	if work == nil {
		t.Fatal("accepted validation state was not durable")
	}
	order.Status = "ready"
	progress.Phase = "finalizing"
	progress.Retired = true
	work = save(work, progress, false)
	if work == nil {
		t.Fatal("finalizing intent was not durable")
	}
	order.Status = "valid"
	order.CertificateURL = "https://acme.example.test/certificate/original"
	save(work, guiissuer.Progress{Phase: "finalizing", Order: &order}, true)
	work = save(work, progress, false)
	if work == nil {
		t.Fatal("known download identity was not retained")
	}
	changed := order
	changed.CertificateURL = "https://acme.example.test/certificate/replacement"
	changedProgress := progress
	changedProgress.Order = &changed
	save(work, changedProgress, true)
	recovered := read(work)
	if recovered.Phase != "finalizing" || recovered.Order == nil || recovered.Order.URI != order.URI || recovered.Order.CertificateURL != order.CertificateURL || recovered.Proof == nil || recovered.Generation != progress.Generation || !recovered.Retired {
		t.Fatal("same-order issuance recovery lost its immutable identity")
	}
	for _, role := range []string{"nethub_web", "nethub_authz", "nethub_issuer"} {
		var allowed bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT has_table_privilege($1,'public.gui_certificate_progress','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, role).Scan(&allowed); err != nil || allowed {
			t.Fatal("private checkpoint table exposed to a runtime role", err)
		}
	}
	ordinary, _ := json.Marshal(recovered)
	if string(ordinary) != "{}" {
		t.Fatal("saved CA metadata reached ordinary JSON")
	}
	t.Log("Durable order creation/finalizing intent, CAS recovery, immutable order/profile/authorization/finalize/download identity and private role boundaries passed")
	return work
}
