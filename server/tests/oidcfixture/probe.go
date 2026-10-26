package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
)

// The independent signed-claim probe uses its own Dex client and one-use state.
// It never creates a NetHub session or bypasses NetHub account admission.
type probeState struct {
	Value, Nonce, Verifier, Configuration string
}

func probeTransport(rootPEM []byte, port int) (*http.Transport, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid fixture port")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("invalid fixture root")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, authority string) (net.Conn, error) {
			host, remotePort, err := net.SplitHostPort(authority)
			if err != nil || remotePort != "443" || (host != "dex-one.test" && host != "dex-two.test") {
				return nil, errors.New("fixture destination refused")
			}
			// Preserve the URL's SNI and hostname verification while routing only
			// the two test authorities to their loopback TLS passthrough listener.
			return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		},
	}, nil
}

func probe(operation, directory string, port int, slug string, input io.Reader, output io.Writer) error {
	if !filepath.IsAbs(directory) || (slug != "one" && slug != "two") {
		return errors.New("invalid probe target")
	}
	root, err := os.ReadFile(filepath.Join(directory, "root.crt"))
	if err != nil {
		return err
	}
	transport, err := probeTransport(root, port)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	raw, err := os.ReadFile(filepath.Join(directory, "credentials.json"))
	if err != nil {
		return err
	}
	var secrets credentials
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fixture redirect refused") }}
	provider, err := authoidc.New(ctx, authoidc.Config{IssuerURL: "https://dex-" + slug + ".test", ClientID: "claim-probe", ClientSecret: secrets.Clients[slug], RedirectURL: consoleOrigin + "/claim-probe", Scopes: []string{"openid", "email"}, HTTPClient: client})
	if err != nil {
		return err
	}
	defer provider.CloseIdleConnections()
	statePath := filepath.Join(directory, "probe-"+slug+".json")
	if operation == "probe-begin" {
		authorization, err := provider.Begin()
		if err != nil {
			return err
		}
		state := authorization.State
		raw, err := json.Marshal(probeState{state.Value, state.Nonce, state.Verifier, state.Configuration})
		if err != nil {
			return err
		}
		file, err := os.OpenFile(statePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = file.Write(raw)
		closed := file.Close()
		if err != nil {
			return err
		}
		if closed != nil {
			return closed
		}
		return json.NewEncoder(output).Encode(map[string]string{"redirect_url": authorization.URL})
	}
	if operation != "probe-finish" {
		return errors.New("invalid probe operation")
	}
	var callback struct{ State, Code string }
	decoder := json.NewDecoder(io.LimitReader(input, 16384))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&callback); err != nil || callback.State == "" || callback.Code == "" {
		return errors.New("invalid probe callback")
	}
	// Only one process can claim the private state before the code exchange.
	claimed := statePath + ".consumed"
	if _, err := os.Stat(claimed); !os.IsNotExist(err) {
		return errors.New("probe already consumed")
	}
	if err := os.Rename(statePath, claimed); err != nil {
		return err
	}
	raw, err = os.ReadFile(claimed)
	if err != nil {
		return err
	}
	var stored probeState
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	assertion, err := provider.Complete(ctx, callback.State, callback.Code, authoidc.State{Value: stored.Value, Nonce: stored.Nonce, Verifier: stored.Verifier, Configuration: stored.Configuration})
	if err != nil {
		return err
	}
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := assertion.Claims(&claims); err != nil || claims.Verified == nil || claims.Email == "" {
		return errors.New("expected signed email claim")
	}
	return json.NewEncoder(output).Encode(map[string]any{"issuer": assertion.ProviderIssuer, "subject": assertion.Subject, "email": claims.Email, "email_verified": *claims.Verified, "signature_nonce_and_PKCE_verified": true})
}
