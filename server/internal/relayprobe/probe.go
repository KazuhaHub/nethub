// Package relayprobe verifies bounded admission paths over pinned relay TLS.
package relayprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"time"

	"github.com/fatedier/yamux"
)

var ErrProbe = errors.New("relay rejection path could not be verified")
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$`)

const ProtocolVersion = "0.71.1"

// Check uses the frp 0.71.1 legacy Login framing over its pinned Yamux transport.
// Login plugins run before control admission. This message has an invalid claim
// and no token, device secret, signed identity, run ID or requested proxy.
func Check(ctx context.Context, address, serverName string, ca []byte) (string, error) {
	id, err := probeIdentity()
	if err != nil {
		return "", ErrProbe
	}
	body, err := json.Marshal(struct {
		Version string            `json:"version"`
		Metas   map[string]string `json:"metas"`
	}{Version: ProtocolVersion, Metas: map[string]string{"device_id": id, "domain_claim": "doctor-invalid-claim"}})
	if err != nil {
		return "", ErrProbe
	}
	response, err := exchangeLogin(ctx, address, serverName, ca, body)
	if err != nil {
		return "", ErrProbe
	}
	return rejectionVersion(response)
}

func probeIdentity() (string, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return "", ErrProbe
	}
	identity[6] = (identity[6] & 15) | 64
	identity[8] = (identity[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", identity[:4], identity[4:6], identity[6:8], identity[8:10], identity[10:]), nil
}

// exchangeLogin closes its fresh control after exactly one bounded Login reply.
// It never sends a proxy request or reuses an existing client's run ID.
func exchangeLogin(ctx context.Context, address, serverName string, ca, body []byte) ([]byte, error) {
	peer, err := netip.ParseAddrPort(address)
	if err != nil || !peer.Addr().IsLoopback() || peer.Port() == 0 || serverName == "" || len(serverName) > 253 || len(ca) == 0 || len(ca) > 65536 || len(body) == 0 || len(body) > 8192 {
		return nil, ErrProbe
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrProbe
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, ErrProbe
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return nil, ErrProbe
	}
	config := yamux.DefaultConfig()
	config.AcceptBacklog = 1
	config.EnableKeepAlive = false
	config.ConnectionWriteTimeout = time.Second
	config.StreamOpenTimeout = time.Second
	config.StreamCloseTimeout = time.Second
	config.LogOutput = io.Discard
	session, err := yamux.Client(connection, config)
	if err != nil {
		return nil, ErrProbe
	}
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		return nil, ErrProbe
	}
	defer stream.Close()
	if stream.SetDeadline(deadline) != nil {
		return nil, ErrProbe
	}
	header := make([]byte, 9)
	header[0] = 'o'
	binary.BigEndian.PutUint64(header[1:], uint64(len(body)))
	if _, err := io.Copy(stream, bytes.NewReader(append(header, body...))); err != nil {
		return nil, ErrProbe
	}
	if _, err := io.ReadFull(stream, header); err != nil || header[0] != '1' {
		return nil, ErrProbe
	}
	length := binary.BigEndian.Uint64(header[1:])
	if length < 2 || length > 4096 {
		return nil, ErrProbe
	}
	response := make([]byte, int(length))
	if _, err := io.ReadFull(stream, response); err != nil {
		return nil, ErrProbe
	}
	return response, nil
}

func rejectionVersion(raw []byte) (string, error) {
	fields, err := loginFields(raw)
	if err != nil || !versionPattern.MatchString(fields["version"]) || fields["run_id"] != "" || fields["error"] != "not_authorized" {
		return "", ErrProbe
	}
	return fields["version"], nil
}

func loginFields(raw []byte) (map[string]string, error) {
	if len(raw) < 2 || len(raw) > 4096 {
		return nil, ErrProbe
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrProbe
	}
	fields := map[string]string{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != "version" && name != "run_id" && name != "error" {
			return nil, ErrProbe
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrProbe
		}
		var value *string
		if decoder.Decode(&value) != nil || value == nil {
			return nil, ErrProbe
		}
		fields[name] = *value
	}
	last, err := decoder.Token()
	var extra any
	if err != nil || last != json.Delim('}') || decoder.Decode(&extra) != io.EOF {
		return nil, ErrProbe
	}
	return fields, nil
}
