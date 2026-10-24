package guiacme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type finalizationBehavior struct {
	issued, loseFinalize, loseCertificate     bool
	finalizes, fetches                        int
	body                                      []byte
	contentType, forceStatus, certificatePath string
	replyCertificatePath                      string
	invalidChain                              func(string) []byte
}

func finalizationFixture(t *testing.T) (*AccountStore, *accountFixture, *orderBehavior, *finalizationBehavior, Order, []byte, string, *x509.CertPool) {
	t.Helper()
	s, f, b := orderFixture(t)
	csr, public := orderRequest(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "separate certificate issuing root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csr)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: root.NotBefore, NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
		DNSNames: []string{orderHost}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, request.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	state := &finalizationBehavior{body: chain, contentType: "application/pem-certificate-chain", certificatePath: "/certificate/one"}
	state.invalidChain = func(kind string) []byte {
		copy := *leaf
		publicKey := request.PublicKey
		switch kind {
		case "wrong-host":
			copy.DNSNames = []string{"other.devices.example.test"}
		case "wrong-key":
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publicKey = &other.PublicKey
		case "expired":
			copy.NotBefore = time.Now().Add(-2 * time.Hour)
			copy.NotAfter = time.Now().Add(-time.Hour)
		}
		der, err := x509.CreateCertificate(rand.Reader, &copy, root, publicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	}
	f.mu.Lock()
	b.mutate = func(response map[string]any) {
		response["status"] = "ready"
		if state.issued {
			response["status"] = "valid"
			response["certificate"] = f.server.URL + state.certificatePath
		}
		if state.forceStatus != "" {
			response["status"] = state.forceStatus
		}
	}
	b.finalization = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		if r.URL.Path == "/finalize/one" {
			var payload struct{ CSR string }
			if json.Unmarshal(body, &payload) != nil {
				w.WriteHeader(400)
				return true
			}
			der, err := base64.RawURLEncoding.DecodeString(payload.CSR)
			if err != nil || !bytes.Equal(der, request.Raw) {
				w.WriteHeader(400)
				return true
			}
			state.finalizes++
			state.issued = true
			if state.loseFinalize {
				w.WriteHeader(503)
				_, _ = w.Write([]byte("private lost finalization response"))
				return true
			}
			path := state.certificatePath
			if state.replyCertificatePath != "" {
				path = state.replyCertificatePath
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid", "certificate": f.server.URL + path})
			return true
		}
		if (r.URL.Path == state.certificatePath || r.URL.Path == state.replyCertificatePath) && len(body) == 0 {
			state.fetches++
			if state.loseCertificate {
				w.WriteHeader(503)
				_, _ = w.Write([]byte("private certificate response"))
				return true
			}
			w.Header().Set("Content-Type", state.contentType)
			_, _ = w.Write(state.body)
			return true
		}
		return false
	}
	f.mu.Unlock()
	order, err := s.CreateOrder(context.Background(), csr, orderHost, public)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return s, f, b, state, order, csr, public, roots
}

func TestFinalizeAndRecoverIssuedOrderWithoutResubmission(t *testing.T) {
	s, f, _, state, order, csr, public, roots := finalizationFixture(t)
	issued, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
	if err != nil || issued.Order.Status != "valid" || issued.Order.CertificateURL == "" || !bytes.Equal(issued.Chain.PEM, state.body) {
		t.Fatalf("finalization: %v", err)
	}
	block, _ := pem.Decode(state.body)
	if issued.Chain.Fingerprint != sha256.Sum256(block.Bytes) {
		t.Fatal("issued fingerprint mismatch")
	}
	if encoded, _ := json.Marshal(issued); string(encoded) != "{}" {
		t.Fatal("issued material appeared in ordinary JSON")
	}
	for range 2 {
		recovered, err := s.FinalizeOrder(context.Background(), issued.Order, csr, public, roots)
		if err != nil || !bytes.Equal(recovered.Chain.PEM, issued.Chain.PEM) {
			t.Fatalf("same certificate recovery: %v", err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if state.finalizes != 1 || state.fetches != 3 {
		t.Fatal("recovery submitted CSR again")
	}
}

func TestFinalizeLostRepliesRecoverSameIssuedMaterial(t *testing.T) {
	for _, lost := range []string{"finalize", "certificate"} {
		t.Run(lost, func(t *testing.T) {
			s, f, _, state, order, csr, public, roots := finalizationFixture(t)
			f.mu.Lock()
			state.loseFinalize = lost == "finalize"
			state.loseCertificate = lost == "certificate"
			f.mu.Unlock()
			if _, err := s.FinalizeOrder(context.Background(), order, csr, public, roots); err != ErrRemote {
				t.Fatalf("ambiguous reply: %v", err)
			}
			f.mu.Lock()
			state.loseFinalize = false
			state.loseCertificate = false
			f.mu.Unlock()
			material, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
			if err != nil || !bytes.Equal(material.Chain.PEM, state.body) {
				t.Fatalf("issued recovery: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if state.finalizes != 1 {
				t.Fatal("lost reply caused another CSR submission")
			}
		})
	}
}

func TestFinalizeAndRecoverPEMWithBlankLines(t *testing.T) {
	s, f, _, state, order, csr, public, roots := finalizationFixture(t)
	canonical := bytes.Clone(state.body)
	f.mu.Lock()
	state.body = bytes.ReplaceAll(state.body, []byte("-----\n-----BEGIN"), []byte("-----\n\n-----BEGIN"))
	f.mu.Unlock()
	issued, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
	if err != nil || !bytes.Equal(issued.Chain.PEM, canonical) {
		t.Fatal("blank-line response failed trusted finalization", err)
	}
	recovered, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
	if err != nil || !bytes.Equal(recovered.Chain.PEM, canonical) {
		t.Fatal("saved order did not recover canonical material", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if state.finalizes != 1 || state.fetches != 2 {
		t.Fatal("recovery created another finalization")
	}
}

func TestFinalizeUsesIndependentRootsAndExactWirePEM(t *testing.T) {
	for _, mutation := range []string{"wrong-roots", "trailing-data", "pem-headers", "wrong-mime", "reordered", "wrong-host", "wrong-key", "expired"} {
		t.Run(mutation, func(t *testing.T) {
			s, f, _, state, order, csr, public, roots := finalizationFixture(t)
			f.mu.Lock()
			switch mutation {
			case "wrong-roots":
				roots = x509.NewCertPool()
				roots.AddCert(f.server.Certificate())
			case "trailing-data":
				state.body = append(state.body, []byte("untrusted trailing bytes")...)
			case "pem-headers":
				block, tail := pem.Decode(state.body)
				block.Headers = map[string]string{"Injected": "value"}
				state.body = append(pem.EncodeToMemory(block), tail...)
			case "wrong-mime":
				state.contentType = "text/plain"
			case "reordered":
				block, tail := pem.Decode(state.body)
				state.body = append(tail, pem.EncodeToMemory(block)...)
			case "wrong-host", "wrong-key", "expired":
				state.body = state.invalidChain(mutation)
			}
			f.mu.Unlock()
			material, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
			if err == nil || len(material.Chain.PEM) != 0 || strings.Contains(err.Error(), "untrusted") {
				t.Fatal("unsafe issuer wire material escaped validation")
			}
		})
	}
}

func TestFinalizeRechecksOrderAfterTheCAResponse(t *testing.T) {
	for _, mutation := range []string{"reply-certificate-url", "changed-authorization"} {
		t.Run(mutation, func(t *testing.T) {
			s, f, b, state, order, csr, public, roots := finalizationFixture(t)
			f.mu.Lock()
			if mutation == "reply-certificate-url" {
				state.replyCertificatePath = "/certificate/other"
			} else {
				original := b.mutate
				b.mutate = func(response map[string]any) {
					original(response)
					if state.issued {
						response["authorizations"] = []string{f.server.URL + "/authz/other"}
					}
				}
			}
			f.mu.Unlock()
			material, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
			if err != ErrOrder || len(material.Chain.PEM) != 0 {
				t.Fatal("intermediate CA response replaced the saved order identity")
			}
		})
	}
}

func TestFinalizeRejectsUnreadyAndChangedIssuedIdentity(t *testing.T) {
	s, f, _, state, order, csr, public, roots := finalizationFixture(t)
	for _, status := range []string{"pending", "processing"} {
		f.mu.Lock()
		state.forceStatus = status
		f.mu.Unlock()
		if _, err := s.FinalizeOrder(context.Background(), order, csr, public, roots); err != ErrNotReady {
			t.Fatalf("unready order: %v", err)
		}
	}
	f.mu.Lock()
	count := state.finalizes
	state.forceStatus = ""
	f.mu.Unlock()
	if count != 0 {
		t.Fatal("unready order submitted CSR")
	}
	before := f.counts()
	if _, err := s.FinalizeOrder(context.Background(), order, csr, public, nil); err != ErrOrder || f.counts() != before {
		t.Fatal("missing independent roots performed network work")
	}
	issued, err := s.FinalizeOrder(context.Background(), order, csr, public, roots)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	state.certificatePath = "/certificate/other"
	beforeFetch := state.fetches
	f.mu.Unlock()
	if _, err := s.FinalizeOrder(context.Background(), issued.Order, csr, public, roots); err != ErrOrder {
		t.Fatal("persisted certificate URL was replaced")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if state.fetches != beforeFetch {
		t.Fatal("changed certificate identity fetched")
	}
}
