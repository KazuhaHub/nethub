package web

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func TestUserAdministrationHTTP(t *testing.T) {
	s, repo, _ := newFixture(t)
	cookie, session := fixtureLogin(t, s)
	id := "00000000-0000-4000-8000-000000000099"
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com", "X-CSRF-Token": session.CSRFToken}
	if got := call(s, "GET", prefix+"/users", "", nil, nil); got.Code != 401 {
		t.Fatal("anonymous user list", got.Code)
	}
	if got := call(s, "GET", prefix+"/users", "", cookie, nil); got.Code != 403 || repo.userReads != 0 {
		t.Fatal("member reached user list", got.Code)
	}
	if got := call(s, "PATCH", prefix+"/users/"+id, `{"disabled":true}`, cookie, headers); got.Code != 403 || repo.userWrites != 0 {
		t.Fatal("member changed user", got.Code)
	}
	for key, record := range repo.sessions {
		record.Role = "admin"
		repo.sessions[key] = record
	}
	repo.userPage = UserPage{Items: []ManagedUser{}}
	if got := call(s, "GET", prefix+"/users?limit=1", "", cookie, nil); got.Code != 200 {
		t.Fatal("admin user list", got.Code)
	}
	for _, query := range []string{"?role=admin", "?limit=0", "?limit=201", "?limit=1&limit=2", "?cursor=invalid", "?limit=%zz"} {
		if got := call(s, "GET", prefix+"/users"+query, "", cookie, nil); got.Code != 400 {
			t.Fatal("invalid user query", query, got.Code)
		}
	}
	before := repo.userWrites
	for _, body := range []string{`{}`, `{"role":"owner"}`, `{"role":null}`, `{"disabled":null}`, `{"disabled":"false"}`, `{"role":"admin","role":"member"}`, `{"password_hash":"secret"}`, `{"disabled":true,"email":"other@example.com"}`} {
		if got := call(s, "PATCH", prefix+"/users/"+id, body, cookie, headers); got.Code != 400 || repo.userWrites != before {
			t.Fatal("invalid user mutation", body, got.Code)
		}
	}
	for _, path := range []string{prefix + "/users/not-a-uuid", prefix + "/users/" + id + "/extra", prefix + "/users/" + id + "?force=true"} {
		if got := call(s, "PATCH", path, `{"disabled":true}`, cookie, headers); got.Code != 400 {
			t.Fatal("invalid user path", got.Code)
		}
	}
	bad := map[string]string{"Content-Type": "application/json", "Origin": "https://foreign.example.com", "X-CSRF-Token": session.CSRFToken}
	if got := call(s, "PATCH", prefix+"/users/"+id, `{"disabled":true}`, cookie, bad); got.Code != 403 || repo.userWrites != before {
		t.Fatal("cross-origin user mutation", got.Code)
	}
	if got := call(s, "PATCH", prefix+"/users/"+id, `{"disabled":true}`, cookie, map[string]string{"Content-Type": "application/json"}); got.Code != 403 {
		t.Fatal("missing CSRF", got.Code)
	}
	repo.userResult = ManagedUser{User: auth.User{ID: id, Role: "member", Email: "target@example.com"}, Disabled: true, Identities: []UserIdentity{}}
	got := call(s, "PATCH", prefix+"/users/"+id, `{"role":"member","disabled":true}`, cookie, headers)
	var user ManagedUser
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &user) != nil || !user.Disabled || repo.userWrites != before+1 || repo.userPatch.Disabled == nil || !*repo.userPatch.Disabled || repo.openID != id || repo.lastIP.String() != "192.0.2.100" {
		t.Fatal("user update not forwarded", got.Code)
	}
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{{ErrLastAdmin, 409, "last_admin"}, {ErrLastLocalAdmin, 409, "last_local_admin"}, {ErrForbidden, 403, "forbidden"}, {ErrUserUnavailable, 404, "not_found"}, {auth.ErrUnauthenticated, 401, "unauthenticated"}, {errors.New("private DB detail"), 500, "internal"}} {
		repo.userErr = tc.err
		got := call(s, "PATCH", prefix+"/users/"+id, `{"disabled":true}`, cookie, headers)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		json.Unmarshal(got.Body.Bytes(), &body)
		if got.Code != tc.status || body.Error.Code != tc.code {
			t.Fatal("user failure mapping", got.Code, body.Error.Code)
		}
	}
}
