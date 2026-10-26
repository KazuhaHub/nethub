package sso

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/auth"
	crewjamsaml "github.com/crewjam/saml"
)

// SAMLIdentityPolicy scopes an already validated assertion to one configured SP
// and IdP. EmailAttribute is the exact Attribute Name, never its FriendlyName.
type SAMLIdentityPolicy struct {
	Issuer, EntityID, EmailAttribute string
}

// SAMLIdentity is a candidate for application admission, not a session or proof
// of an invitation. The caller must also consume a browser-bound request and
// check the live provider, account and invitation in its admission transaction.
type SAMLIdentity struct {
	Issuer, Subject, Email string
}

func (SAMLIdentity) String() string     { return "SAMLIdentity(redacted)" }
func (v SAMLIdentity) GoString() string { return v.String() }

// Identity accepts only a persistent NameID from authcore's verified result.
// It does not parse XML or infer identity from a mailbox or display attribute.
func (p SAMLIdentityPolicy) Identity(assertion *authsaml.Assertion) (SAMLIdentity, error) {
	valid := func(value string, limit int) bool {
		return len(value) > 0 && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) != "" && !strings.ContainsRune(value, 0)
	}
	if !valid(p.Issuer, 2048) || !valid(p.EntityID, 2048) || !valid(p.EmailAttribute, 1024) || assertion == nil ||
		assertion.Issuer != p.Issuer || assertion.NameIDFormat != string(crewjamsaml.PersistentNameIDFormat) || !valid(assertion.NameID, 4096) ||
		assertion.NameQualifier != "" && assertion.NameQualifier != p.Issuer ||
		assertion.SPNameQualifier != "" && assertion.SPNameQualifier != p.EntityID {
		return SAMLIdentity{}, ErrFlow
	}
	// An omitted qualifier and its explicit expected value have the same scope.
	// SPProvidedID is an alternate identifier, not a replacement for NameID.
	// A length-safe tuple preserves significant NameID bytes and prevents either
	// issuer or pairwise SP scope from collapsing into another account key.
	tuple, _ := json.Marshal([4]string{p.Issuer, p.EntityID, assertion.NameIDFormat, assertion.NameID})
	digest := sha256.Sum256(tuple)
	identity := SAMLIdentity{Issuer: p.Issuer, Subject: "saml:v1:" + base64.RawURLEncoding.EncodeToString(digest[:])}
	values := assertion.AttributesByName[p.EmailAttribute]
	if len(values) > 1 {
		return SAMLIdentity{}, ErrFlow
	}
	if len(values) == 1 {
		email, err := auth.NormalizeEmail(values[0])
		if err != nil {
			return SAMLIdentity{}, ErrFlow
		}
		identity.Email = email
	}
	return identity, nil
}
