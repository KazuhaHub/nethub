package sso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func metadataDocument(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Signing certificates are pinned keys, independent of public TLS trust.
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:example:idp">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/login?tenant=example"/>
</IDPSSODescriptor></EntityDescriptor>`, base64.StdEncoding.EncodeToString(der))
}

func TestSAMLMetadataExplicitSelectionAndInheritedExpiry(t *testing.T) {
	document := metadataDocument(t)
	group := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">` +
		strings.ReplaceAll(document, "urn:example:idp", "urn:example:other") +
		`<EntitiesDescriptor validUntil="2029-01-01T00:00:00Z">` + document + `</EntitiesDescriptor></EntitiesDescriptor>`
	metadata, err := ParseSAMLMetadata([]byte(group), "urn:example:idp")
	if err != nil {
		t.Fatal(err)
	}
	wantSigned := metadata.IDPSSODescriptors[0].WantAuthnRequestsSigned
	if metadata.EntityID != "urn:example:idp" || metadata.ValidUntil.Format(time.RFC3339) != "2029-01-01T00:00:00Z" || wantSigned == nil || !*wantSigned {
		t.Fatal("explicit selection lost its deadline or request-signing requirement")
	}
	if metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location != "https://idp.example.com/login?tenant=example" {
		t.Fatal("legitimate endpoint query was changed")
	}
}

func TestSAMLMetadataRejectsUnsafeDocuments(t *testing.T) {
	valid := metadataDocument(t)
	cases := map[string]string{
		"empty":                      "",
		"oversized":                  strings.Repeat(" ", (1<<20)+1),
		"wrong entity":               strings.ReplaceAll(valid, "urn:example:idp", "urn:example:other"),
		"duplicate entity attribute": strings.Replace(valid, `entityID="urn:example:idp"`, `entityID="urn:example:other" entityID="urn:example:idp"`, 1),
		"wrong root namespace":       strings.Replace(valid, samlMetadataNamespace, "urn:wrong", 1),
		"wrong role namespace":       strings.Replace(valid, "<IDPSSODescriptor ", `<IDPSSODescriptor xmlns="urn:wrong" `, 1),
		"wrong key namespace":        strings.ReplaceAll(valid, "http://www.w3.org/2000/09/xmldsig#", "urn:wrong"),
		"duplicate document":         valid + valid,
		"trailing text":              valid + "unexpected",
		"DTD":                        `<!DOCTYPE EntityDescriptor [<!ENTITY x "value">]>` + valid,
		"processing instruction":     `<?external fetch?>` + valid,
		"non SAML2":                  strings.Replace(valid, "urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:1.0:protocol", 1),
		"HTTP endpoint":              strings.Replace(valid, "https://idp.example.com", "http://idp.example.com", 1),
		"endpoint credentials":       strings.Replace(valid, "https://idp.example.com", "https://user:secret@idp.example.com", 1),
		"endpoint fragment":          strings.Replace(valid, "?tenant=example", "#fragment", 1),
		"endpoint reserved query":    strings.Replace(valid, "?tenant=example", "?%53AMLRequest=injected", 1),
		"endpoint malformed query":   strings.Replace(valid, "?tenant=example", "?tenant=%zz", 1),
		"no redirect":                strings.Replace(valid, "bindings:HTTP-Redirect", "bindings:HTTP-POST", 1),
		"encryption key only":        strings.Replace(valid, `use="signing"`, `use="encryption"`, 1),
		"malformed certificate":      strings.Replace(valid, "<ds:X509Certificate>", "<ds:X509Certificate>!", 1),
		"duplicate entity":           `<EntitiesDescriptor xmlns="` + samlMetadataNamespace + `">` + valid + valid + `</EntitiesDescriptor>`,
		"deep XML":                   `<EntitiesDescriptor xmlns="` + samlMetadataNamespace + `">` + strings.Repeat("<EntitiesDescriptor>", 65) + valid + strings.Repeat("</EntitiesDescriptor>", 65) + `</EntitiesDescriptor>`,
		"too many entities":          `<EntitiesDescriptor xmlns="` + samlMetadataNamespace + `">` + strings.Repeat(valid, 129) + `</EntitiesDescriptor>`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSAMLMetadata([]byte(document), "urn:example:idp"); err != ErrSAMLMetadata {
				t.Fatalf("expected bounded generic refusal, got %v", err)
			}
		})
	}
	for _, identifier := range []string{"", " urn:example:idp", strings.Repeat("x", 4097)} {
		if _, err := ParseSAMLMetadata([]byte(valid), identifier); err != ErrSAMLMetadata {
			t.Fatal("ambiguous identifier accepted")
		}
	}
}

func TestSAMLMetadataSigningRequirementReachesAuthcore(t *testing.T) {
	metadata, err := ParseSAMLMetadata([]byte(metadataDocument(t)), "urn:example:idp")
	if err != nil {
		t.Fatal(err)
	}
	config := samlConfig()
	config.IDPMetadata = metadata
	if _, err := NewSAMLProvider(config); err == nil {
		t.Fatal("trusted IdP signing requirement was ignored without an SP key")
	}
}
