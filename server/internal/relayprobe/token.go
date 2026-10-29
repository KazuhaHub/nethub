package relayprobe

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var devicePattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var runPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

const tokenRejection = "token in login doesn't match token from configuration"

// LoginCredential belongs only in private memory and verified local TLS. Its
// claim must authorize an existing device; this helper creates no database row.
type LoginCredential struct {
	Token       string `json:"-"`
	DeviceID    string `json:"-"`
	DomainClaim string `json:"-"`
}

func (LoginCredential) String() string   { return "[private relay Login credential]" }
func (LoginCredential) GoString() string { return "[private relay Login credential]" }

// LoginToken distinguishes actual admission from the pinned token-auth refusal.
// Policy/plugin errors, transport failures and ambiguous replies are errors.
// It uses a fresh unique user and empty run/client IDs, sends no proxy request,
// closes the new control immediately, and never returns raw server data.
func LoginToken(ctx context.Context, address, serverName string, ca []byte, credential LoginCredential) (bool, error) {
	if !tokenPattern.MatchString(credential.Token) || !devicePattern.MatchString(credential.DeviceID) ||
		len(credential.DomainClaim) == 0 || len(credential.DomainClaim) > 3116 ||
		strings.ContainsAny(credential.DomainClaim, " \t\r\n") {
		return false, ErrProbe
	}
	id, err := probeIdentity()
	if err != nil {
		return false, ErrProbe
	}
	timestamp := time.Now().Unix()
	body, err := json.Marshal(struct {
		Version      string            `json:"version"`
		User         string            `json:"user"`
		PrivilegeKey string            `json:"privilege_key"`
		Timestamp    int64             `json:"timestamp"`
		Metas        map[string]string `json:"metas"`
	}{ProtocolVersion, "nethub-token-probe-" + id, tokenLoginKey(credential.Token, timestamp), timestamp,
		map[string]string{"device_id": credential.DeviceID, "domain_claim": credential.DomainClaim}})
	if err != nil {
		return false, ErrProbe
	}
	response, err := exchangeLogin(ctx, address, serverName, ca, body)
	if err != nil {
		return false, ErrProbe
	}
	return tokenLoginResult(response)
}

// frp 0.71.1 requires this legacy wire digest inside verified TLS. It is not a
// password-storage or general-purpose authentication primitive.
func tokenLoginKey(token string, timestamp int64) string {
	sum := md5.Sum([]byte(token + strconv.FormatInt(timestamp, 10)))
	return hex.EncodeToString(sum[:])
}

func tokenLoginResult(raw []byte) (bool, error) {
	fields, err := loginFields(raw)
	if err != nil || fields["version"] != ProtocolVersion {
		return false, ErrProbe
	}
	if fields["error"] == "" && runPattern.MatchString(fields["run_id"]) {
		return true, nil
	}
	if fields["run_id"] == "" && fields["error"] == tokenRejection {
		return false, nil
	}
	return false, ErrProbe
}
