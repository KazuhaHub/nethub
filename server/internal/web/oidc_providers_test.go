package web

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func TestOIDCProviderAdministrationHTTP(t *testing.T) {
	s, repo, _ := newFixture(t)
	cookie, session := fixtureLogin(t, s)
	id := "00000000-0000-4000-8000-000000000099"
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com", "X-CSRF-Token": session.CSRFToken}
	path := prefix + "/oidc-providers"
	if got := call(s, "GET", path, "", nil, nil); got.Code != 401 {
		t.Fatal("anonymous list", got.Code)
	}
	if got := call(s, "GET", path, "", cookie, nil); got.Code != 403 || repo.oidcReads != 0 {
		t.Fatal("member list", got.Code)
	}
	if got := call(s, "POST", path, "{}", cookie, headers); got.Code != 403 || repo.oidcWrites != 0 {
		t.Fatal("member write", got.Code)
	}
	for key, record := range repo.sessions {
		record.Role = "admin"
		repo.sessions[key] = record
	}
	repo.oidcResult = OIDCProvider{ID: id, Slug: "company", HasClientSecret: true, Scopes: []string{"openid", "email", "profile"}}
	repo.oidcPage = OIDCProviderPage{Items: []OIDCProvider{repo.oidcResult}}
	got := call(s, "GET", path+"?limit=1", "", cookie, nil)
	var page OIDCProviderPage
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].RedirectURI != "https://console.example.com/api/v1/console/oidc/company/callback" {
		t.Fatal("provider list", got.Code)
	}
	for _, query := range []string{"?limit=0", "?limit=201", "?limit=1&limit=2", "?cursor=invalid", "?client_secret=true", "?limit=%zz"} {
		if got := call(s, "GET", path+query, "", cookie, nil); got.Code != 400 {
			t.Fatal("bad query", got.Code)
		}
	}
	input := OIDCProviderInput{Slug: "company", DisplayName: "Company", IssuerURL: "https://idp.example", ClientID: "console", ClientSecret: "private-client-fixture"}
	raw, _ := json.Marshal(input)
	// Omitted optional fields receive server defaults. A null value never means
	// keep the old secret, clear it, or silently choose a default.
	var create map[string]any
	json.Unmarshal(raw, &create)
	delete(create, "scopes")
	delete(create, "enabled")
	raw, _ = json.Marshal(create)
	got = call(s, "POST", path, string(raw), cookie, headers)
	if got.Code != 201 || repo.oidcInput.ClientSecret != input.ClientSecret || repo.oidcInput.Enabled || len(repo.oidcInput.Scopes) != 3 || repo.lastIP.String() != "192.0.2.100" || strings.Contains(got.Body.String(), input.ClientSecret) || strings.Contains(got.Body.String(), `"client_secret":`) {
		t.Fatal("provider create boundary", got.Code)
	}
	before := repo.oidcWrites
	for _, body := range []string{`{}`, `{"enabled":null}`, `{"client_secret":null}`, `{"scopes":null}`, `{"client_id":123}`, `{"slug":"other"}`, `{"enabled":true,"enabled":false}`, `{"client_secret_enc":"bad"}`} {
		if got := call(s, "PATCH", path+"/"+id, body, cookie, headers); got.Code != 400 || repo.oidcWrites != before {
			t.Fatal("bad provider patch", body, got.Code)
		}
	}
	for _, method := range []string{"PATCH", "DELETE"} {
		if got := call(s, method, path+"/"+id, `{"enabled":false}`, cookie, map[string]string{"Content-Type": "application/json"}); got.Code != 403 {
			t.Fatal("missing mutation CSRF", method, got.Code)
		}
		if got := call(s, method, path+"/bad", "", cookie, headers); got.Code != 400 {
			t.Fatal("bad provider ID", got.Code)
		}
	}
	got = call(s, "PATCH", path+"/"+id, `{"enabled":false}`, cookie, headers)
	if got.Code != 200 || repo.oidcPatch.ClientSecret != nil || repo.oidcPatch.Enabled == nil || *repo.oidcPatch.Enabled || repo.openID != id {
		t.Fatal("patch omitted credential lost", got.Code)
	}
	got = call(s, "PATCH", path+"/"+id, `{"client_secret":""}`, cookie, headers)
	if got.Code != 200 || repo.oidcPatch.ClientSecret == nil || *repo.oidcPatch.ClientSecret != "" {
		t.Fatal("explicit public credential clear lost", got.Code)
	}
	got = call(s, "DELETE", path+"/"+id, "", cookie, headers)
	if got.Code != 204 || got.Body.Len() != 0 {
		t.Fatal("provider deletion", got.Code)
	}
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{ErrOIDCDiscovery, 422, "oidc_discovery_failed"}, {ErrProviderInUse, 409, "provider_in_use"}, {ErrProviderChanged, 409, "provider_changed"}, {ErrProviderSlugTaken, 409, "slug_taken"}, {ErrOIDCNotFound, 404, "not_found"}, {ErrProviderInput, 400, "invalid_request"}, {auth.ErrUnauthenticated, 401, "unauthenticated"}, {ErrForbidden, 403, "forbidden"}, {errors.New("private upstream detail"), 500, "internal"},
	} {
		repo.oidcErr = tc.err
		got := call(s, "PATCH", path+"/"+id, `{"enabled":false}`, cookie, headers)
		if got.Code != tc.status || !strings.Contains(got.Body.String(), tc.code) || strings.Contains(got.Body.String(), "private upstream") {
			t.Fatal("provider error projection", tc.code, got.Code)
		}
	}
}

func TestOIDCProviderInputPolicy(t *testing.T) {
	valid := OIDCProviderInput{Slug: "company", DisplayName: "Company", IssuerURL: "https://idp.example/realm", ClientID: "client"}
	if got, err := NormalizeOIDCInput(valid); err != nil || len(got.Scopes) != 3 || got.Enabled {
		t.Fatal("default provider policy", err)
	}
	for _, change := range []func(*OIDCProviderInput){
		func(v *OIDCProviderInput) { v.Slug = "../bad" }, func(v *OIDCProviderInput) { v.DisplayName = "" }, func(v *OIDCProviderInput) { v.ClientID = "\nclient" }, func(v *OIDCProviderInput) { v.IssuerURL = "http://idp.example" }, func(v *OIDCProviderInput) { v.IssuerURL = "https://user@idp.example" }, func(v *OIDCProviderInput) { v.IssuerURL = "https://idp.example?" }, func(v *OIDCProviderInput) { v.ClientSecret = strings.Repeat("a", 16385) }, func(v *OIDCProviderInput) { v.Scopes = []string{} }, func(v *OIDCProviderInput) { v.Scopes = []string{"email"} }, func(v *OIDCProviderInput) { v.Scopes = []string{"openid", "openid"} }, func(v *OIDCProviderInput) { v.Scopes = []string{"openid", "bad scope"} }, func(v *OIDCProviderInput) { v.Scopes = []string{"openid", "bad\\scope"} },
	} {
		input := valid
		change(&input)
		if _, err := NormalizeOIDCInput(input); !errors.Is(err, ErrProviderInput) {
			t.Fatal("invalid configuration accepted")
		}
	}
}
