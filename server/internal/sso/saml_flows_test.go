package sso

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/beevik/etree"
	cs "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

type samlMemoryFlow struct {
	input    SAMLFlowInput
	consumed bool
}
type samlFlowTestRepository struct {
	*flowTestRepository
	samlProvider SAMLLoginProvider
	samlFlows    map[string]*samlMemoryFlow
}

func (r *samlFlowTestRepository) SAMLLoginProviders(context.Context) ([]Choice, error) {
	return []Choice{{Protocol: "saml", Slug: r.samlProvider.Slug, DisplayName: r.samlProvider.DisplayName}}, nil
}
func (r *samlFlowTestRepository) SAMLLoginProvider(_ context.Context, slug string) (SAMLLoginProvider, error) {
	if slug != r.samlProvider.Slug {
		return SAMLLoginProvider{}, ErrFlow
	}
	return r.samlProvider, nil
}
func (r *samlFlowTestRepository) SaveSAMLFlow(_ context.Context, input SAMLFlowInput) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samlFlows[input.State] = &samlMemoryFlow{input: input}
	return time.Now().Add(FlowLifetime), nil
}
func (r *samlFlowTestRepository) ConsumeSAMLFlow(_ context.Context, slug, state string, browser []byte) (ConsumedSAMLFlow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	flow := r.samlFlows[state]
	if flow == nil || flow.consumed || slug != flow.input.Provider.Slug || !hmac.Equal(browser, flow.input.BrowserDigest) {
		return ConsumedSAMLFlow{}, ErrFlow
	}
	flow.consumed = true
	return ConsumedSAMLFlow{ID: "00000000-0000-4000-8000-000000000001", RequestID: flow.input.RequestID, Provider: flow.input.Provider}, nil
}

// The issuer below creates actual enveloped XML signatures. Account admission
// uses an in-memory observer here; genuine SQL and deployed IdP checks are separate.
func signedSAMLResponse(t *testing.T, key crypto.Signer, certificate *x509.Certificate, requestID, assertionID, issuer, audience, acs string, expired bool) string {
	t.Helper()
	now := time.Now().UTC()
	expiry := now.Add(2 * time.Minute)
	if expired {
		expiry = now.Add(-time.Hour)
	}
	assertion := &cs.Assertion{ID: assertionID, IssueInstant: now, Version: "2.0", Issuer: cs.Issuer{Value: issuer},
		Subject:             &cs.Subject{NameID: &cs.NameID{Format: string(cs.PersistentNameIDFormat), Value: "persistent-person", NameQualifier: issuer, SPNameQualifier: audience}, SubjectConfirmations: []cs.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData: &cs.SubjectConfirmationData{InResponseTo: requestID, Recipient: acs, NotOnOrAfter: expiry}}}},
		Conditions:          &cs.Conditions{NotBefore: now.Add(-2 * time.Minute), NotOnOrAfter: expiry, AudienceRestrictions: []cs.AudienceRestriction{{Audience: cs.Audience{Value: audience}}}},
		AuthnStatements:     []cs.AuthnStatement{{AuthnInstant: now, SessionIndex: "session-" + assertionID, AuthnContext: cs.AuthnContext{AuthnContextClassRef: &cs.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}}}},
		AttributeStatements: []cs.AttributeStatement{{Attributes: []cs.Attribute{{Name: "mail", Values: []cs.AttributeValue{{Type: "xs:string", Value: "person@example.com"}}}}}},
	}
	signing, err := dsig.NewSigningContext(key, [][]byte{certificate.Raw})
	if err != nil {
		t.Fatal(err)
	}
	signing.IdAttribute = "ID"
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err = signing.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := signing.SignEnveloped(assertion.Element())
	if err != nil {
		t.Fatal(err)
	}
	response := (&cs.Response{ID: "response-" + assertionID, InResponseTo: requestID, Version: "2.0", IssueInstant: now, Destination: acs, Issuer: &cs.Issuer{Value: issuer}, Status: cs.Status{StatusCode: cs.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}}).Element()
	response.AddChild(signed)
	document := etree.NewDocument()
	document.SetRoot(response)
	raw, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestSAMLServiceGenuineSignedResponse(t *testing.T) {
	material := func() (crypto.Signer, *x509.Certificate) {
		t.Helper()
		bundle, err := NewSAMLSigningIdentity(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(bundle)
		key, certificate, err := ParseSAMLSigningIdentity(bundle)
		if err != nil {
			t.Fatal(err)
		}
		return key, certificate
	}
	idpKey, idpCertificate := material()
	spKey, spCertificate := material()
	const issuer = "urn:example:test-idp"
	const entity = "https://console.example.com/api/v1/console/saml/company/metadata"
	const acs = "https://console.example.com/api/v1/console/saml/company/callback"
	metadata := &cs.EntityDescriptor{EntityID: issuer, IDPSSODescriptors: []cs.IDPSSODescriptor{{SSODescriptor: cs.SSODescriptor{RoleDescriptor: cs.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol", KeyDescriptors: []cs.KeyDescriptor{{Use: "signing", KeyInfo: cs.KeyInfo{X509Data: cs.X509Data{X509Certificates: []cs.X509Certificate{{Data: base64.StdEncoding.EncodeToString(idpCertificate.Raw)}}}}}}}}, SingleSignOnServices: []cs.Endpoint{{Binding: cs.HTTPRedirectBinding, Location: "https://idp.example.com/login"}}}}}
	repository := &samlFlowTestRepository{flowTestRepository: &flowTestRepository{}, samlProvider: SAMLLoginProvider{ID: "provider-saml", Slug: "company", Revision: 1, EmailAttribute: "mail", Config: authsaml.Config{IDPMetadata: metadata, Key: spKey, Certificate: spCertificate, ReplayCache: authsaml.NewMemoryReplayCache(100)}}, samlFlows: map[string]*samlMemoryFlow{}}
	sessions, err := auth.NewService(repository, auth.Config{IdleTimeout: time.Hour, AbsoluteTimeout: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := NewOutbound(nil)
	if err != nil {
		t.Fatal(err)
	}
	outbound.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	service, err := NewSAMLService("https://console.example.com", repository, sessions, outbound)
	if err != nil {
		t.Fatal(err)
	}
	begin := func() (StartResult, string, string) {
		t.Helper()
		start, err := service.Start(context.Background(), "company", "")
		if err != nil {
			t.Fatal(err)
		}
		redirect, err := url.Parse(start.RedirectURL)
		if err != nil {
			t.Fatal(err)
		}
		state := redirect.Query().Get("RelayState")
		return start, state, repository.samlFlows[state].input.RequestID
	}
	ip := netip.MustParseAddr("192.0.2.230")
	start, state, requestID := begin()
	response := signedSAMLResponse(t, idpKey, idpCertificate, requestID, "signed-accepted", issuer, entity, acs, false)
	if _, consumed, err := service.Complete(context.Background(), "company", state, response, strings.Repeat("A", 43), ip, "test"); err == nil || consumed {
		t.Fatal("wrong browser consumed a real request")
	}
	result, consumed, err := service.Complete(context.Background(), "company", state, response, start.BrowserToken, ip, "test")
	if err != nil || !consumed || result.Token == "" || repository.admissions != 1 || repository.identity.Protocol != "saml" || !repository.identity.SignedEmail || repository.identity.EmailVerified || !strings.HasPrefix(repository.identity.Subject, "saml:v1:") {
		t.Fatal("genuine signed SAML admission failed", err)
	}
	if _, consumed, err := service.Complete(context.Background(), "company", state, response, start.BrowserToken, ip, "test"); err == nil || consumed || repository.admissions != 1 {
		t.Fatal("consumed browser request replayed")
	}
	for index, change := range []struct {
		name, issuer, audience, acs, request, assertion string
		expired, tampered                               bool
	}{
		{name: "issuer", issuer: "urn:other"}, {name: "audience", audience: "https://other.example.com"}, {name: "destination", acs: "https://other.example.com/acs"}, {name: "request", request: "unrequested"}, {name: "expiry", expired: true}, {name: "assertion replay", assertion: "signed-accepted"},
		{name: "signature tampering", tampered: true},
	} {
		t.Run(change.name, func(t *testing.T) {
			start, state, requestID := begin()
			i, a, d := issuer, entity, acs
			if change.issuer != "" {
				i = change.issuer
			}
			if change.audience != "" {
				a = change.audience
			}
			if change.acs != "" {
				d = change.acs
			}
			if change.request != "" {
				requestID = change.request
			}
			assertionID := fmt.Sprintf("signed-rejected-%d", index)
			if change.assertion != "" {
				assertionID = change.assertion
			}
			response := signedSAMLResponse(t, idpKey, idpCertificate, requestID, assertionID, i, a, d, change.expired)
			if change.tampered {
				raw, err := base64.StdEncoding.DecodeString(response)
				if err != nil {
					t.Fatal(err)
				}
				changed := strings.Replace(string(raw), "persistent-person", "changed-person", 1)
				if changed == string(raw) {
					t.Fatal("signature tamper control changed no signed value")
				}
				response = base64.StdEncoding.EncodeToString([]byte(changed))
			}
			if _, consumed, err := service.Complete(context.Background(), "company", state, response, start.BrowserToken, ip, "test"); err == nil || !consumed || repository.admissions != 1 {
				t.Fatal("invalid genuine signed assertion reached admission", err)
			}
		})
	}
}
