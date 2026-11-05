package relaycert

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestConstrainedRelayTrustOpenSSLInteroperability(t *testing.T) {
	openssl := os.Getenv("NETHUB_TEST_OPENSSL")
	if openssl == "" {
		var err error
		openssl, err = exec.LookPath("openssl")
		if err != nil {
			t.Skip("OpenSSL is required for independent trust interoperability")
		}
	}
	const name = "console.example.com"
	var authorities [3]Material
	for index := range authorities {
		material, err := Create(name, time.Now())
		if err != nil {
			t.Fatal("relay fixture authority creation failed")
		}
		authorities[index] = material
	}
	directory := t.TempDir()
	public := map[string][]byte{
		"overlap.pem":      append(append([]byte{}, authorities[0].CA...), authorities[1].CA...),
		"original.pem":     authorities[0].CA,
		"successor.pem":    authorities[1].CA,
		"old-leaf.pem":     authorities[0].Certificate,
		"next-leaf.pem":    authorities[1].Certificate,
		"foreign-leaf.pem": authorities[2].Certificate,
	}
	for filename, data := range public {
		if os.WriteFile(filepath.Join(directory, filename), data, 0600) != nil {
			t.Fatal("public fixture certificate write failed")
		}
	}
	verify := func(bundle, certificate, hostname string, endpoint bool) bool {
		t.Helper()
		arguments := []string{"verify", "-CAfile", filepath.Join(directory, bundle)}
		if endpoint {
			arguments = append(arguments, "-no-CApath", "-no-CAstore", "-check_ss_sig", "-purpose", "sslserver", "-verify_hostname", hostname)
		}
		arguments = append(arguments, filepath.Join(directory, certificate))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := exec.CommandContext(ctx, openssl, arguments...).Run()
		if ctx.Err() != nil {
			t.Fatal("independent certificate check timed out")
		}
		if err == nil {
			return true
		}
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatal("independent certificate checker unavailable")
		}
		return false
	}
	for _, leaf := range []string{"old-leaf.pem", "next-leaf.pem"} {
		if !verify("overlap.pem", leaf, name, true) {
			t.Fatal("valid constrained relay leaf refused under overlap")
		}
		if verify("overlap.pem", leaf, "other.example.com", true) {
			t.Fatal("wrong relay hostname accepted")
		}
	}
	if verify("overlap.pem", "foreign-leaf.pem", name, true) || verify("original.pem", "next-leaf.pem", name, true) {
		t.Fatal("unpublished or retired authority accepted")
	}
	if !verify("original.pem", "old-leaf.pem", name, true) {
		t.Fatal("original relay leaf refused after retirement")
	}
	t.Logf("Independent OpenSSL overlap and retirement verified both constrained relay leaves; wrong host/foreign root refused; original-root-as-end-entity refused=%t; successor-root-as-end-entity refused=%t", !verify("overlap.pem", "original.pem", name, false), !verify("overlap.pem", "successor.pem", name, false))
}
