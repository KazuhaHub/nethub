package sso

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	authsaml "github.com/KazuhaHub/authcore/saml"
	crewjamsaml "github.com/crewjam/saml"
)

func samlIdentityFixture() (SAMLIdentityPolicy, *authsaml.Assertion) {
	p := SAMLIdentityPolicy{Issuer: "https://idp.example.com", EntityID: "https://console.example.com/sp/one", EmailAttribute: "urn:example:mail"}
	a := &authsaml.Assertion{Issuer: p.Issuer, NameID: "pairwise-stable-id", NameIDFormat: string(crewjamsaml.PersistentNameIDFormat),
		NameQualifier: p.Issuer, SPNameQualifier: p.EntityID, AttributesByName: map[string][]string{p.EmailAttribute: {"Member@Example.com"}}}
	return p, a
}

func TestSAMLIdentityUsesStableScopedNameID(t *testing.T) {
	p, a := samlIdentityFixture()
	first, err := p.Identity(a)
	if err != nil || first.Email != "member@example.com" || first.Issuer != p.Issuer || !strings.HasPrefix(first.Subject, "saml:v1:") {
		t.Fatal("persistent assertion did not map to a scoped identity", err)
	}
	// Neither mailbox changes nor an alternate SP identifier rebind NameID.
	a.AttributesByName[p.EmailAttribute] = []string{"new@example.com"}
	a.SPProvidedID = "alternate-sp-assigned-identifier"
	a.NameQualifier, a.SPNameQualifier = "", ""
	second, err := p.Identity(a)
	if err != nil || first.Subject != second.Subject || second.Email != "new@example.com" {
		t.Fatal("mailbox, alternate ID or omitted expected qualifiers changed the account key", err)
	}
	for _, change := range []func(*SAMLIdentityPolicy, *authsaml.Assertion){
		func(p *SAMLIdentityPolicy, a *authsaml.Assertion) { p.Issuer += "/second"; a.Issuer = p.Issuer },
		func(p *SAMLIdentityPolicy, a *authsaml.Assertion) { p.EntityID += "/second" },
		func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.NameID += " " },
	} {
		p, a := samlIdentityFixture()
		a.NameQualifier, a.SPNameQualifier = "", ""
		change(&p, a)
		other, err := p.Identity(a)
		if err != nil || other.Subject == first.Subject {
			t.Fatal("issuer, SP scope or significant NameID bytes collapsed", err)
		}
	}
	for _, value := range []string{fmt.Sprint(first), fmt.Sprintf("%#v", first)} {
		if strings.Contains(value, first.Email) || strings.Contains(value, first.Subject) || strings.Contains(value, first.Issuer) {
			t.Fatal("identity formatting exposed account information")
		}
	}
}

func TestSAMLIdentityRefusesAmbiguousOrUnstableClaims(t *testing.T) {
	cases := map[string]func(*SAMLIdentityPolicy, *authsaml.Assertion){
		"issuer": func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.Issuer += "/other" },
		"transient": func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) {
			a.NameIDFormat = string(crewjamsaml.TransientNameIDFormat)
		},
		"mailbox identifier": func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) {
			a.NameIDFormat = string(crewjamsaml.EmailAddressNameIDFormat)
		},
		"missing format": func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.NameIDFormat = "" },
		"empty ID":       func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.NameID = " " },
		"oversized ID":   func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.NameID = strings.Repeat("a", 4097) },
		"invalid UTF8":   func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.NameID = string([]byte{255}) },
		"IdP qualifier":  func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.NameQualifier += "/other" },
		"SP qualifier":   func(_ *SAMLIdentityPolicy, a *authsaml.Assertion) { a.SPNameQualifier += "/other" },
		"multiple mail values": func(p *SAMLIdentityPolicy, a *authsaml.Assertion) {
			a.AttributesByName[p.EmailAttribute] = []string{"a@example.com", "b@example.com"}
		},
		"display mailbox": func(p *SAMLIdentityPolicy, a *authsaml.Assertion) {
			a.AttributesByName[p.EmailAttribute] = []string{"Alice <a@example.com>"}
		},
		"empty policy": func(p *SAMLIdentityPolicy, _ *authsaml.Assertion) { p.EntityID = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, a := samlIdentityFixture()
			change(&p, a)
			if identity, err := p.Identity(a); !errors.Is(err, ErrFlow) || identity != (SAMLIdentity{}) {
				t.Fatal("unsafe assertion exposed an identity")
			}
		})
	}
	p, _ := samlIdentityFixture()
	if _, err := p.Identity(nil); !errors.Is(err, ErrFlow) {
		t.Fatal("nil assertion accepted")
	}
}

func TestSAMLIdentityDoesNotResolveEmailByFriendlyName(t *testing.T) {
	p, a := samlIdentityFixture()
	delete(a.AttributesByName, p.EmailAttribute)
	a.Attributes = map[string][]string{p.EmailAttribute: {"attacker@example.com"}}
	identity, err := p.Identity(a)
	if err != nil || identity.Email != "" || identity.Subject == "" {
		t.Fatal("FriendlyName collision supplied an email or missing email erased stable identity", err)
	}
}
