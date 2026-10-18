package auth

import (
	"errors"
	"net/http"
	"net/url"
)

type OriginPolicy struct{ origin string }

func NewOriginPolicy(origin string) (*OriginPolicy, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("console origin must be an absolute HTTPS origin without a path")
	}
	return &OriginPolicy{origin: origin}, nil
}

// Check requires an exact origin for pre-login mutations. Authenticated
// mutations may omit Origin only when they carry a valid synchronizer token.
func (p *OriginPolicy) Check(request *http.Request, required bool) bool {
	values := request.Header.Values("Origin")
	if len(values) == 0 {
		return !required
	}
	return len(values) == 1 && values[0] == p.origin
}
