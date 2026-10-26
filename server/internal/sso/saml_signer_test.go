package sso

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSAMLSigningIdentityAndSharedRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bundle, err := NewSAMLSigningIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	key, certificate, err := ParseSAMLSigningIdentity(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle) > 16*1024 || certificate.IsCA || certificate.NotAfter.Before(now.AddDate(1, 0, 0)) {
		t.Fatal("invalid SP signing identity")
	}
	metadata, err := ParseSAMLMetadata([]byte(metadataDocument(t)), "urn:example:idp")
	if err != nil {
		t.Fatal(err)
	}
	config := samlConfig()
	config.Key = key
	config.Certificate = certificate
	config.IDPMetadata = metadata
	config.SignAuthnRequests = true
	provider, err := NewSAMLProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	request, err := provider.NewAuthnRequest("browser-bound-state")
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(request.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	parts := map[string]string{}
	for _, part := range strings.Split(redirect.RawQuery, "&") {
		name, _, _ := strings.Cut(part, "=")
		parts[name] = part
	}
	for _, name := range []string{"SAMLRequest", "RelayState", "SigAlg", "Signature"} {
		if parts[name] == "" {
			t.Fatal("shared provider omitted request signature fields")
		}
	}
	input := parts["SAMLRequest"] + "&" + parts["RelayState"] + "&" + parts["SigAlg"]
	digest := sha256.Sum256([]byte(input))
	signature, err := base64.StdEncoding.DecodeString(redirect.Query().Get("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	if err = rsa.VerifyPKCS1v15(certificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal("actual shared request signature failed independent verification", err)
	}
	if redirect.Query().Get("tenant") != "example" {
		t.Fatal("IdP endpoint query was lost")
	}
	public, err := provider.MetadataXML()
	if err != nil || bytes.Contains(public, []byte("PRIVATE KEY")) {
		t.Fatal("private key entered public SP metadata", err)
	}
	for name, bad := range map[string][]byte{"empty": nil, "oversized": bytes.Repeat([]byte("x"), 16*1024+1), "prefix": append([]byte("unexpected"), bundle...), "trailing": append(append([]byte{}, bundle...), []byte("unexpected")...), "wrong block": bytes.Replace(bundle, []byte("BEGIN PRIVATE KEY"), []byte("BEGIN PUBLIC KEY"), 1)} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseSAMLSigningIdentity(bad); err != ErrSAMLSigningIdentity {
				t.Fatal("unsafe private bundle accepted", err)
			}
		})
	}
}
