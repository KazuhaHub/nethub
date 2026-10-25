package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func TestInvitationAdministrationHTTP(t *testing.T) {
	s, repo, logs := newFixture(t)
	cookie, session := fixtureLogin(t, s)
	id := "00000000-0000-4000-8000-000000000088"
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{88}, 32))
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com", "X-CSRF-Token": session.CSRFToken}
	if response := call(s, "GET", prefix+"/invites", "", nil, nil); response.Code != 401 {
		t.Fatal("anonymous invite list", response.Code)
	}
	for _, method := range []string{"GET", "POST", "DELETE"} {
		path := prefix + "/invites"
		body := `{"email":"new@example.com","role":"member"}`
		if method == "GET" {
			body = ""
		}
		if method == "DELETE" {
			path += "/" + id
			body = ""
		}
		if response := call(s, method, path, body, cookie, headers); response.Code != 403 {
			t.Fatal("member invitation administration", method, response.Code)
		}
	}
	for key, record := range repo.sessions {
		record.Role = "admin"
		repo.sessions[key] = record
	}
	for _, body := range []string{`{}`, `{"email":"invalid","role":"member"}`, `{"email":"new@example.com","role":"owner"}`, `{"email":"new@example.com","role":"member","provider_id":"invalid"}`, `{"email":"new@example.com","role":"member","token":"chosen"}`, `{"email":"new@example.com","role":"member","role":"admin"}`} {
		if response := call(s, "POST", prefix+"/invites", body, cookie, headers); response.Code != 400 || repo.inviteIssued != 0 {
			t.Fatal("invalid invite issuance", response.Code)
		}
	}
	if response := call(s, "POST", prefix+"/invites", `{"email":"new@example.com","role":"member"}`, cookie, map[string]string{"Content-Type": "application/json"}); response.Code != 403 {
		t.Fatal("issuance without CSRF", response.Code)
	}
	repo.inviteGrant = IssuedInvitation{ID: id, Token: token, ExpiresAt: time.Now().Add(72 * time.Hour)}
	response := call(s, "POST", prefix+"/invites", `{"email":" New@Example.com ","role":"member"}`, cookie, headers)
	var grant struct {
		ID  string `json:"id"`
		URL string `json:"invite_url"`
	}
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &grant) != nil || repo.inviteInput.Email != "new@example.com" || repo.inviteIssued != 1 {
		t.Fatal("invitation issuance", response.Code)
	}
	u, err := url.Parse(grant.URL)
	if err != nil || u.Scheme != "https" || u.Host != "console.example.com" || u.Path != "/invite" || u.Fragment != token || u.RawQuery != "" {
		t.Fatal("invitation token escaped its fragment", err)
	}
	repo.invitePage = InvitationPage{Items: []Invitation{{ID: id, Email: "new@example.com", Role: "member"}}}
	response = call(s, "GET", prefix+"/invites?limit=1", "", cookie, nil)
	if response.Code != 200 || bytes.Contains(response.Body.Bytes(), []byte(token)) {
		t.Fatal("pending list exposed token", response.Code)
	}
	for _, query := range []string{"?limit=0", "?limit=201", "?cursor=invalid", "?limit=1&limit=2", "?owner=other"} {
		if got := call(s, "GET", prefix+"/invites"+query, "", cookie, nil); got.Code != 400 {
			t.Fatal("invalid invite query", query, got.Code)
		}
	}
	if got := call(s, "DELETE", prefix+"/invites/"+id, `{}`, cookie, headers); got.Code != 400 || repo.inviteWithdrawn != 0 {
		t.Fatal("withdrawal accepted a body", got.Code)
	}
	if got := call(s, "DELETE", prefix+"/invites/"+id, "", cookie, headers); got.Code != 204 || repo.inviteWithdrawn != 1 || repo.openID != id {
		t.Fatal("invitation withdrawal", got.Code)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{ErrUserExists, 409}, {ErrInviteProviderUnavailable, 404}, {ErrForbidden, 403}, {auth.ErrUnauthenticated, 401}, {errors.New("private database detail"), 500}} {
		repo.inviteError = tc.err
		if got := call(s, "POST", prefix+"/invites", `{"email":"new@example.com","role":"member"}`, cookie, headers); got.Code != tc.status {
			t.Fatal("invitation error mapping", got.Code)
		}
	}
	if bytes.Contains(logs.Bytes(), []byte(token)) || bytes.Contains(logs.Bytes(), []byte("private database detail")) {
		t.Fatal("invitation logs exposed private data")
	}
}

func TestInvitationClaimHTTP(t *testing.T) {
	s, repo, logs := newFixture(t)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32))
	password := "a local invitation passphrase"
	body, _ := json.Marshal(map[string]string{"token": token, "password": password})
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com"}
	for _, path := range []string{"/invites/inspect", "/invites/accept"} {
		if got := call(s, "POST", prefix+path, string(body), nil, map[string]string{"Content-Type": "application/json"}); got.Code != 403 {
			t.Fatal("prelogin invitation without Origin", path, got.Code)
		}
	}
	for _, path := range []string{"/invites/inspect?token=hidden", "/invites/accept?token=hidden"} {
		if got := call(s, "POST", prefix+path, string(body), nil, headers); got.Code != 400 {
			t.Fatal("invitation accepted URL parameters", path, got.Code)
		}
	}
	repo.inviteInfo = auth.InvitationInfo{Email: "new@example.com", Role: "member", ExpiresAt: time.Now().Add(time.Hour), PasswordAllowed: true, Providers: []auth.InvitationProvider{}}
	inspection, _ := json.Marshal(map[string]string{"token": token})
	got := call(s, "POST", prefix+"/invites/inspect", string(inspection), nil, headers)
	expected, _ := auth.InvitationDigest(token)
	if got.Code != 200 || repo.inviteInspected != 1 || !bytes.Equal(expected, repo.inviteDigest) || bytes.Contains(got.Body.Bytes(), []byte(token)) {
		t.Fatal("public invitation inspection", got.Code)
	}
	weak, _ := json.Marshal(map[string]string{"token": token, "password": "short"})
	if got := call(s, "POST", prefix+"/invites/accept", string(weak), nil, headers); got.Code != 422 || repo.inviteAccepted != 0 {
		t.Fatal("weak invitation password reached repository", got.Code)
	}
	repo.inviteError = auth.ErrInviteInvalid
	got = call(s, "POST", prefix+"/invites/accept", string(body), nil, headers)
	if got.Code != 404 || repo.inviteFailures != 1 || len(got.Result().Cookies()) != 0 {
		t.Fatal("invalid invitation produced a session or omitted failure audit", got.Code)
	}
	repo.inviteAuditError = errors.New("private audit failure")
	if got := call(s, "POST", prefix+"/invites/accept", string(body), nil, headers); got.Code != 500 {
		t.Fatal("invitation audit failure ignored", got.Code)
	}
	repo.inviteError = nil
	repo.inviteAuditError = nil
	got = call(s, "POST", prefix+"/invites/accept", string(body), nil, headers)
	var session auth.Session
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &session) != nil || session.User.Role != "member" {
		t.Fatal("local invitation activation", got.Code)
	}
	cookies := got.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Name != "__Host-nethub_session" || cookies[0].Path != "/" || cookies[0].Domain != "" || bytes.Contains(got.Body.Bytes(), []byte(cookies[0].Value)) {
		t.Fatal("invitation session cookie boundary")
	}
	if response := call(s, "GET", prefix+"/session", "", cookies[0], nil); response.Code != 200 || !bytes.Contains(response.Body.Bytes(), []byte(session.CSRFToken)) {
		t.Fatal("invitation session synchronizer not recoverable", response.Code)
	}
	if response := call(s, "GET", prefix+"/users", "", cookies[0], nil); response.Code != 403 {
		t.Fatal("invited member gained administrator access", response.Code)
	}
	for _, secret := range []string{token, password, cookies[0].Value} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Fatal("invitation credential logged")
		}
	}
}
