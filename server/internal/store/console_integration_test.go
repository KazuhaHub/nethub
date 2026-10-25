package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testConsoleHTTP(t *testing.T, ctx context.Context, owner, db, authz *sql.DB, tenant, otherTenant string) {
	t.Helper()
	if _, err := SoleTenant(ctx, db); err == nil {
		t.Fatal("multi-tenant database accepted by single-tenant startup")
	}
	hash, err := auth.HashPassword("an isolated API fixture passphrase")
	if err != nil {
		t.Fatal(err)
	}
	createUser := func(email, role string) string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,$4) RETURNING id`, tenant, email, role, hash).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	member := createUser("api-member@example.com", "member")
	other := createUser("api-other@example.com", "member")
	admin := createUser("api-admin@example.com", "admin")
	defer owner.ExecContext(ctx, `UPDATE users SET role='member' WHERE id=$1`, admin)
	device := func(deviceTenant, actor, subdomain string) string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,hostname,platform,device_secret_hash,subdomain,agent_protocol_version,last_seen_at) VALUES($1,$2,'fixture firewall','opnsense','private fixture hash',$3,'fixture',clock_timestamp()) RETURNING id`, deviceTenant, actor, subdomain).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	memberDevice := device(tenant, member, "api-member")
	otherDevice := device(tenant, other, "api-other")
	var foreignOwner string
	if err = owner.QueryRowContext(ctx, `SELECT id FROM users WHERE tenant_id=$1 LIMIT 1`, otherTenant).Scan(&foreignOwner); err != nil {
		t.Fatal(err)
	}
	foreignDevice := device(otherTenant, foreignOwner, "api-foreign")
	repository := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}}
	service, err := auth.NewService(&repository.AuthStore, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := web.New(web.Config{Origin: origin, DeviceDomain: "router.example.com", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Logger: slog.New(slog.NewJSONHandler(logs, nil))}, service, repository)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	newClient := func() *http.Client {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: server.Client().Transport, Jar: jar, Timeout: 5 * time.Second}
	}
	client, adminClient := newClient(), newClient()
	request := func(client *http.Client, method, path, body, csrf string, want int) ([]byte, *http.Response) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, origin+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Forwarded-For", "192.0.2.100")
		if method == "POST" {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.StatusCode, want, data)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing HTTP response protection")
		}
		return data, response
	}
	login := func(client *http.Client, email string) (auth.Session, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"email": email, "password": "an isolated API fixture passphrase"})
		data, response := request(client, "POST", "/api/v1/console/login", string(body), "", 200)
		var session auth.Session
		if err := json.Unmarshal(data, &session); err != nil {
			t.Fatal(err)
		}
		cookies := response.Cookies()
		if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" {
			t.Fatal("invalid session cookie over HTTPS")
		}
		if bytes.Contains(data, []byte(cookies[0].Value)) {
			t.Fatal("bearer returned in JSON")
		}
		return session, cookies[0].Value
	}
	session, bearer := login(client, "api-member@example.com")
	adminSession, _ := login(adminClient, "api-admin@example.com")
	if session.User.ID != member || adminSession.User.ID != admin {
		t.Fatal("login actor mismatch")
	}
	var memberLastSeen time.Time
	for _, test := range []struct {
		client     *http.Client
		user, path string
	}{{client, member, "/api/v1/console/session"}, {adminClient, admin, "/api/v1/console/users"}} {
		var before, after time.Time
		if err = owner.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE user_id=$1`, test.user).Scan(&before); err != nil {
			t.Fatal(err)
		}
		r, e := http.NewRequestWithContext(ctx, "GET", origin+test.path, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("X-NetHub-Background", "1")
		response, e := test.client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		_, e = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if e != nil || response.StatusCode != 200 {
			t.Fatal("passive HTTP read failed", test.path, response.StatusCode, e)
		}
		if err = owner.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE user_id=$1`, test.user).Scan(&after); err != nil || !after.Equal(before) {
			t.Fatal("background read extended session activity", test.path, err)
		}
		if test.user == member {
			memberLastSeen = before
		}
	}
	data, _ := request(client, "GET", "/api/v1/console/session", "", "", 200)
	if !bytes.Contains(data, []byte(session.CSRFToken)) || !bytes.Contains(data, []byte(`"signed_in":true`)) {
		t.Fatal("session recovery failed")
	}
	var activeLastSeen time.Time
	if err = owner.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE user_id=$1`, member).Scan(&activeLastSeen); err != nil || !activeLastSeen.After(memberLastSeen) {
		t.Fatal("explicit session read did not record activity", err)
	}
	t.Log("Background user inventory and authority refresh preserved actual PostgreSQL last_seen_at; explicit session lookup advanced it")
	data, _ = request(client, "GET", "/api/v1/console/devices?online=true&limit=1", "", "", 200)
	var page web.DevicePage
	if err = json.Unmarshal(data, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != memberDevice || page.Items[0].Owner.ID != member || page.Items[0].URL != "https://api-member.router.example.com:8443" || page.NextCursor != nil {
		t.Fatal("member device scope or URL mismatch")
	}
	if bytes.Contains(data, []byte("private fixture hash")) || bytes.Contains(data, []byte("device_secret_hash")) {
		t.Fatal("device secret exposed")
	}
	seen := map[string]bool{}
	path := "/api/v1/console/devices?limit=1"
	for range 20 {
		data, _ = request(adminClient, "GET", path, "", "", 200)
		if err = json.Unmarshal(data, &page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatal("duplicate device across pages")
			}
			seen[item.ID] = true
		}
		if page.NextCursor == nil {
			break
		}
		path = "/api/v1/console/devices?limit=1&cursor=" + url.QueryEscape(*page.NextCursor)
	}
	if !seen[memberDevice] || !seen[otherDevice] || seen[foreignDevice] {
		t.Fatal("admin pagination crossed tenant or omitted visible devices")
	}
	openPath := "/api/v1/console/devices/" + memberDevice + "/open"
	request(client, "POST", openPath, `{}`, "wrong", 403)
	request(client, "POST", openPath, `{"source_ip":"203.0.113.1"}`, session.CSRFToken, 400)
	request(client, "POST", "/api/v1/console/devices/"+otherDevice+"/open", `{}`, session.CSRFToken, 404)
	data, _ = request(client, "POST", openPath, `{}`, session.CSRFToken, 200)
	var access web.DeviceAccess
	if err = json.Unmarshal(data, &access); err != nil || access.URL != "https://api-member.router.example.com:8443" {
		t.Fatal("HTTP open did not return assigned URL", err)
	}
	var source string
	var grantExpiry time.Time
	if err = owner.QueryRowContext(ctx, `SELECT host(source_ip),expires_at FROM device_access_grants WHERE device_id=$1 AND user_id=$2`, memberDevice, member).Scan(&source, &grantExpiry); err != nil || source != "192.0.2.100" || !grantExpiry.Equal(access.ExpiresAt) {
		t.Fatal("HTTP open lost authenticated actor and trusted proxy source", err)
	}
	request(client, "POST", "/api/v1/console/enroll-tokens", `{}`, "wrong", 403)
	request(client, "POST", "/api/v1/console/enroll-tokens", `{"expires_at":"2099-01-01T00:00:00Z"}`, session.CSRFToken, 400)
	data, _ = request(client, "POST", "/api/v1/console/enroll-tokens", `{}`, session.CSRFToken, 201)
	var issued web.EnrollToken
	if err = json.Unmarshal(data, &issued); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(issued.Token)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid enrollment entropy/encoding")
	}
	digest := sha256.Sum256(raw)
	var creator string
	var lifetime float64
	if err = owner.QueryRowContext(ctx, `SELECT created_by_user_id,extract(epoch FROM expires_at-created_at) FROM enroll_tokens WHERE token_hash=$1`, digest[:]).Scan(&creator, &lifetime); err != nil || creator != member || lifetime != 900 {
		t.Fatal("token owner, digest, or default lifetime mismatch")
	}
	for attempt := 0; attempt < 2; attempt++ {
		var count int
		if err = authz.QueryRowContext(ctx, `SELECT count(*) FROM consume_enroll_token($1)`, digest[:]).Scan(&count); err != nil || count != 1-attempt {
			t.Fatal("HTTP-issued token was not single-use")
		}
	}
	for range 4 {
		request(client, "POST", "/api/v1/console/enroll-tokens", `{}`, session.CSRFToken, 201)
	}
	_, limited := request(client, "POST", "/api/v1/console/enroll-tokens", `{}`, session.CSRFToken, 429)
	if limited.Header.Get("Retry-After") == "" {
		t.Fatal("rate response lacks retry guidance")
	}
	data, _ = request(client, "GET", "/api/v1/console/session", "", "", 200)
	if bytes.Contains(data, []byte(issued.Token)) {
		t.Fatal("issued enrollment token was replayed in a later response")
	}
	wrongBody, _ := request(client, "POST", "/api/v1/console/login", `{"email":"api-member@example.com","password":"wrong"}`, "", 401)
	absentBody, _ := request(client, "POST", "/api/v1/console/login", `{"email":"absent@example.com","password":"wrong"}`, "", 401)
	if !bytes.Equal(wrongBody, absentBody) {
		t.Fatal("login response reveals account existence")
	}
	// Audit failure must roll back logout, session creation, and token issuance.
	if _, err = owner.ExecContext(ctx, `REVOKE EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) FROM nethub_web`); err != nil {
		t.Fatal(err)
	}
	defer owner.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) TO nethub_web`)
	var sessionsBefore, tokensBefore int
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE tenant_id=$1`, tenant).Scan(&sessionsBefore); err != nil {
		t.Fatal(err)
	}
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM enroll_tokens WHERE tenant_id=$1`, tenant).Scan(&tokensBefore); err != nil {
		t.Fatal(err)
	}
	request(adminClient, "POST", "/api/v1/console/enroll-tokens", `{}`, adminSession.CSRFToken, 500)
	request(client, "POST", "/api/v1/console/logout", `{}`, session.CSRFToken, 500)
	_, failedLogin := request(client, "POST", "/api/v1/console/login", `{"email":"api-member@example.com","password":"an isolated API fixture passphrase"}`, "", 500)
	if len(failedLogin.Cookies()) != 0 {
		t.Fatal("unaudited login issued a cookie")
	}
	var sessionsAfter, tokensAfter int
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE tenant_id=$1`, tenant).Scan(&sessionsAfter); err != nil {
		t.Fatal(err)
	}
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM enroll_tokens WHERE tenant_id=$1`, tenant).Scan(&tokensAfter); err != nil {
		t.Fatal(err)
	}
	if sessionsAfter != sessionsBefore || tokensAfter != tokensBefore {
		t.Fatal("audit failure left a partial mutation")
	}
	if _, err = owner.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) TO nethub_web`); err != nil {
		t.Fatal(err)
	}
	request(client, "POST", "/api/v1/console/logout", `{}`, session.CSRFToken, 204)
	request(client, "GET", "/api/v1/console/devices", "", "", 401)
	_, _ = login(client, "api-member@example.com")
	if _, err = owner.ExecContext(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1`, member); err != nil {
		t.Fatal(err)
	}
	request(client, "GET", "/api/v1/console/devices", "", "", 401)
	disabledBody, _ := request(client, "POST", "/api/v1/console/login", `{"email":"api-member@example.com","password":"an isolated API fixture passphrase"}`, "", 401)
	if !bytes.Equal(wrongBody, disabledBody) {
		t.Fatal("login response reveals account disable state")
	}
	var auditData string
	if err = owner.QueryRowContext(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('action',action,'actor',actor_id,'payload',payload))::text,'[]') FROM audit_log WHERE tenant_id=$1 AND action IN ('auth.login','auth.login_failed','auth.logout','enroll_token.created')`, tenant).Scan(&auditData); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(auditData, "192.0.2.100") || !strings.Contains(auditData, member) || !strings.Contains(auditData, "auth.login_failed") {
		t.Fatal("audit source or actor missing")
	}
	for _, secret := range []string{bearer, session.CSRFToken, issued.Token, hash, "an isolated API fixture passphrase"} {
		if strings.Contains(auditData, secret) || strings.Contains(logs.String(), secret) {
			t.Fatal("credential leaked into audit or application log")
		}
	}
}
