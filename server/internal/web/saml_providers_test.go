package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSAMLProviderInputMatchesSessionLimits(t *testing.T) {
	input := SAMLProviderInput{Slug: "company", DisplayName: "Company", EntityID: strings.Repeat("x", 2048), EmailAttribute: "mail", MetadataXML: "bounded"}
	if _, err := NormalizeSAMLInput(input); err != nil {
		t.Fatal("maximum session issuer refused", err)
	}
	input.EntityID += "x"
	if _, err := NormalizeSAMLInput(input); err != ErrProviderInput {
		t.Fatal("provider accepted an issuer the session service cannot admit", err)
	}
}

func TestSAMLProviderAdministrationHTTP(t *testing.T) {
	s, repo, _ := newFixture(t)
	cookie, session := fixtureLogin(t, s)
	path := prefix + "/saml-providers"
	id := "00000000-0000-4000-8000-000000000098"
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com", "X-CSRF-Token": session.CSRFToken}
	if got := call(s, "GET", path, "", nil, nil); got.Code != 401 {
		t.Fatal("anonymous list", got.Code)
	}
	if got := call(s, "POST", path, "{}", cookie, headers); got.Code != 403 || repo.samlWrites != 0 {
		t.Fatal("member write", got.Code)
	}
	for key, record := range repo.sessions {
		record.Role = "admin"
		repo.sessions[key] = record
	}
	repo.samlResult = SAMLProvider{ID: id, Slug: "company", HasSigningKey: true}
	repo.samlPage = SAMLProviderPage{Items: []SAMLProvider{repo.samlResult}}
	got := call(s, "GET", path, "", cookie, nil)
	if got.Code != 200 || !strings.Contains(got.Body.String(), "/saml/company/metadata") || strings.Contains(got.Body.String(), "sp_key_enc") || strings.Contains(got.Body.String(), "metadata_xml") {
		t.Fatal("unsafe list projection", got.Code)
	}
	// Large administrator metadata is allowed here without widening other APIs.
	input := SAMLProviderInput{Slug: "company", DisplayName: "Company", EntityID: "urn:company:idp", EmailAttribute: "mail", MetadataXML: strings.Repeat("x", maxBody+1)}
	raw, _ := json.Marshal(input)
	got = call(s, "POST", path, string(raw), cookie, headers)
	if got.Code != 201 || repo.samlInput.MetadataXML != input.MetadataXML || repo.samlInput.Enabled || repo.lastIP.String() != "192.0.2.100" {
		t.Fatal("create boundary", got.Code)
	}
	before := repo.samlWrites
	for _, body := range []string{`{}`, `{"enabled":null}`, `{"enabled":true,"enabled":false}`, `{"slug":"other"}`, `{"sp_key_enc":"private"}`, `{"metadata_xml":4}`} {
		if got := call(s, "PATCH", path+"/"+id, body, cookie, headers); got.Code != 400 || repo.samlWrites != before {
			t.Fatal("unsafe patch", got.Code)
		}
	}
	if got := call(s, "PATCH", path+"/"+id, `{"enabled":false}`, cookie, map[string]string{"Content-Type": "application/json"}); got.Code != 403 {
		t.Fatal("missing CSRF", got.Code)
	}
	if got := call(s, "PATCH", path+"/"+id, `{"enabled":false}`, cookie, headers); got.Code != 200 || repo.samlPatch.Enabled == nil || *repo.samlPatch.Enabled {
		t.Fatal("disable", got.Code)
	}
	if got := call(s, "DELETE", path+"/"+id, "", cookie, headers); got.Code != 204 {
		t.Fatal("delete", got.Code)
	}
	for _, failure := range []struct {
		err    error
		status int
		code   string
	}{{ErrSAMLMetadata, 422, "saml_metadata_invalid"}, {ErrSAMLNotFound, 404, "not_found"}, {ErrProviderChanged, 409, "provider_changed"}} {
		repo.samlErr = failure.err
		if got := call(s, "PATCH", path+"/"+id, `{"enabled":true}`, cookie, headers); got.Code != failure.status || !strings.Contains(got.Body.String(), failure.code) {
			t.Fatal("error projection", got.Code)
		}
	}
	repo.samlErr = nil
	if got := call(s, "GET", prefix+"/saml/company/metadata", "", nil, nil); got.Code != 200 || !strings.HasPrefix(got.Header().Get("Content-Type"), "application/samlmetadata+xml") {
		t.Fatal("public metadata", got.Code)
	}
	if got := call(s, "POST", prefix+"/saml/company/metadata", "", nil, nil); got.Code != 405 {
		t.Fatal("metadata method", got.Code)
	}
}
