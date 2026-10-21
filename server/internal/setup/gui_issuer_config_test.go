package setup

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestGUIIssuerPolicyRequiresExplicitExistingAccountAndCleanupBinding(t *testing.T) {
	root := t.TempDir()
	policy := GUIIssuerPolicy{Version: 1, AccountDirectory: filepath.Join(root, "account"), DirectoryURL: "https://acme.example.test/directory", ContactEmail: "issuer@example.test", AdditionalOrigins: []string{}, HTTPPolicyFile: filepath.Join(root, "http01.json"), CleanupTimer: "nethub-http01-cleanup.timer"}
	encode := func(p GUIIssuerPolicy) []byte { b, _ := json.Marshal(p); return b }
	if _, err := decodeGUIIssuerPolicy(encode(policy)); err != nil {
		t.Fatal("valid explicit policy refused", err)
	}
	for _, change := range []func(*GUIIssuerPolicy){
		func(p *GUIIssuerPolicy) { p.Version = 2 },
		func(p *GUIIssuerPolicy) { p.AccountDirectory = "" },
		func(p *GUIIssuerPolicy) { p.AccountDirectory = "relative" },
		func(p *GUIIssuerPolicy) { p.DirectoryURL = "http://acme.example.test/directory" },
		func(p *GUIIssuerPolicy) { p.AdditionalOrigins = nil },
		func(p *GUIIssuerPolicy) { p.HTTPPolicyFile = "" },
		func(p *GUIIssuerPolicy) { p.CleanupTimer = "../unrelated.timer" },
		func(p *GUIIssuerPolicy) { p.CertificateRootsFile = "relative" },
	} {
		p := policy
		change(&p)
		if _, err := decodeGUIIssuerPolicy(encode(p)); err == nil {
			t.Fatal("unsafe or incomplete policy accepted")
		}
	}
	valid := encode(policy)
	for _, data := range [][]byte{append(bytes.Clone(valid), valid...), append(bytes.Clone(valid[:len(valid)-1]), []byte(`,"private_key":"not-accepted"}`)...), []byte(`{"version":1,"version":1}`)} {
		if _, err := decodeGUIIssuerPolicy(data); err == nil {
			t.Fatal("ambiguous/secret-bearing policy accepted")
		}
	}
}
